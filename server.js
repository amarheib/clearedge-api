/**
 * ClearEdge Backend — Express API (v0.1)
 * -------------------------------------------------
 * Endpoints:
 *  POST /api/validate       -> Validate invoice (multipart file or JSON body)
 *  POST /api/case           -> Create support case with report + contact
 *  GET  /api/health         -> Liveness probe
 *
 * Notes:
 *  - PDF parsing intentionally NOT included in MVP.
 *  - In-memory store for cases; replace with DB in production.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import multer from 'multer';
import { XMLParser } from 'fast-xml-parser';
import rateLimit from 'express-rate-limit';

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB

app.use(helmet());
app.use(cors({ origin:https://clearedge2-2woj.vercel.app/}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.use(limiter);

const cases = [];

app.get('/api/health', (_, res) => res.json({ ok: true }));

app.post('/api/validate', upload.single('file'), async (req, res) => {
  try {
    let invoice = null;
    let source = 'json';

    if (req.file) {
      const name = (req.file.originalname || '').toLowerCase();
      if (name.endsWith('.json')) {
        invoice = JSON.parse(req.file.buffer.toString('utf8'));
        source = 'json';
      } else if (name.endsWith('.csv')) {
        invoice = csvToInvoice(req.file.buffer.toString('utf8'));
        source = 'csv';
      } else if (name.endsWith('.xml')) {
        const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '' });
        const xml = parser.parse(req.file.buffer.toString('utf8'));
        invoice = xmlToInvoice(xml);
        source = 'xml';
      } else if (name.endsWith('.pdf')) {
        return res.status(400).json({ error: 'PDF אינו נתמך ב-MVP. העלה JSON/CSV/XML או שלח אובייקט invoice בגוף הבקשה.' });
      } else {
        return res.status(400).json({ error: 'פורמט קובץ לא נתמך. תומך: JSON, CSV, XML.' });
      }
    } else if (req.body && req.body.invoice) {
      invoice = typeof req.body.invoice === 'string' ? JSON.parse(req.body.invoice) : req.body.invoice;
      source = req.body.source || 'json';
    } else {
      return res.status(400).json({ error: 'לא התקבל קובץ או שדה invoice בגוף הבקשה.' });
    }

    const report = validateInvoice(invoice);
    return res.json({ ...report, source });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'שגיאה בעיבוד הקובץ/הנתונים' });
  }
});

app.post('/api/case', (req, res) => {
  const { report, contact, attachments } = req.body || {};
  if (!report || !contact?.email) {
    return res.status(400).json({ error: 'חסר report או contact.email' });
  }
  const caseId = 'CE-' + Math.random().toString(36).slice(2, 8).toUpperCase();
  const item = { caseId, report, contact, attachments: attachments || [], createdAt: new Date().toISOString(), status: 'OPEN' };
  cases.push(item);
  return res.json({ caseId, status: 'OPEN' });
});

function validateInvoice(inv) {
  const issues = [];

  if (!inv?.supplierVat) issues.push(issue('SUPPLIER_VAT', 'HIGH', 'חסר מספר עוסק של הספק', 'הוסף מספר עוסק (9 ספרות) בשדה supplierVat'));
  if (!inv?.customerVat) issues.push(issue('CUSTOMER_VAT', 'MED', 'חסר מספר עוסק של הלקוח', 'הוסף מספר עוסק בשדה customerVat'));
  if (!inv?.date) issues.push(issue('DATE', 'MED', 'חסר תאריך חשבונית', 'הוסף תאריך בפורמט YYYY-MM-DD'));
  if (inv?.total == null) issues.push(issue('TOTAL', 'HIGH', 'חסר סכום סופי (total)', 'הוסף סכום כולל'));
  if (inv?.vat == null) issues.push(issue('VAT', 'MED', 'חסר סכום מע\"מ (vat)', 'הוסף סכום מע\"מ'));

  if (inv?.supplierVat && !/^\d{9}$/.test(String(inv.supplierVat))) issues.push(issue('SUPPLIER_VAT_FMT', 'HIGH', 'פורמט עוסק ספק לא תקין', 'ודא 9 ספרות ללא מקפים'));
  if (inv?.customerVat && !/^\d{9}$/.test(String(inv.customerVat))) issues.push(issue('CUSTOMER_VAT_FMT', 'MED', 'פורמט עוסק לקוח לא תקין', 'ודא 9 ספרות ללא מקפים'));

  const VAT_RATE = 0.17;
  if (isNum(inv.total) && isNum(inv.vat)) {
    const subtotal = Number(inv.total) - Number(inv.vat);
    const expected = round2(subtotal * VAT_RATE);
    const diff = Math.abs(expected - Number(inv.vat));
    if (diff > 1) issues.push(issue('VAT_MISMATCH', 'MED', `מע\"מ לא תואם את שיעור ${VAT_RATE * 100}%`, 'בדוק חישובי ביניים/עיגול סכומים'));
    if (subtotal <= 0) issues.push(issue('SUBTOTAL_NEG', 'HIGH', 'סכום לפני מע\"מ לא תקין (שלילי/אפס)', 'בדוק פריטים וסיכומים'));
  }

  const supported = ['ILS', 'USD', 'EUR'];
  if (inv?.currency && !supported.includes(inv.currency)) {
    issues.push(issue('CURRENCY_UNSUPPORTED', 'LOW', 'מטבע לא נתמך ב-MVP', 'השתמש ב-ILS/USD/EUR או השאר ריק'));
  }

  if (inv?.invoiceId && String(inv.invoiceId).length < 6) {
    issues.push(issue('INVOICE_ID_WEAK', 'LOW', 'מזהה חשבונית קצר/לא ייחודי מספיק', 'הגדל ל-6+ תווים/ספרות'));
  }

  let score = 100 - issues.reduce((acc, it) => acc + (it.severity === 'HIGH' ? 25 : it.severity === 'MED' ? 12 : 5), 0);
  score = Math.max(0, Math.min(100, score));
  const level = score >= 85 ? 'GREEN' : score >= 60 ? 'YELLOW' : 'RED';

  return { level, score, issues, meta: extractMeta(inv) };
}

function issue(code, severity, message, fix) {
  return { code, severity, message, fix };
}

function isNum(v) { return typeof v === 'number' && !isNaN(v) }
function round2(n) { return Math.round(n * 100) / 100 }

function extractMeta(inv) {
  return {
    supplierVat: inv?.supplierVat ?? '',
    customerVat: inv?.customerVat ?? '',
    total: inv?.total ?? '',
    vat: inv?.vat ?? '',
    date: inv?.date ?? '',
    currency: inv?.currency ?? 'ILS'
  };
}

function csvToInvoice(text) {
  const [headerLine, ...rows] = text.trim().split(/\r?\n/);
  const headers = headerLine.split(',').map((s) => s.trim());
  const row = (rows[0] || '').split(',').map((s) => s.trim());
  const obj = {};
  headers.forEach((h, i) => { obj[h] = coerce(row[i]); });
  return obj;
}

function xmlToInvoice(xml) {
  const inv = xml.invoice || xml.Invoice || {};
  const mapKey = (k) => ({ supplierVat: ['supplierVat','supplier','supplier_vat','supplierVAT'], customerVat: ['customerVat','customer','customer_vat','customerVAT'], total: ['total','grandTotal','amount'], vat: ['vat','VAT','tax'], date: ['date','invoiceDate'], currency: ['currency'], invoiceId: ['invoiceId','id','number'] })[k];
  const out = {};
  ['supplierVat','customerVat','total','vat','date','currency','invoiceId'].forEach((k) => {
    const keys = mapKey(k);
    let val = '';
    for (const cand of keys) { if (inv[cand] != null) { val = inv[cand]; break; } }
    out[k] = coerce(val);
  });
  return out;
}

function coerce(v) {
  if (v == null) return '';
  if (typeof v === 'number') return v;
  if (typeof v !== 'string') return String(v);
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v;
  if (/^\d+(\.\d+)?$/.test(v)) return Number(v);
  return v;
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`ClearEdge API running on :${PORT}`));
