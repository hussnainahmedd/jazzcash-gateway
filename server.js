const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Calculate JazzCash HMAC-SHA256 Secure Hash
function generateSecureHash(payload, integritySalt) {
    // 1. Sort the keys starting with "pp" (case-insensitive, covers pp_ and ppmpf_) alphabetically, excluding pp_SecureHash
    const sortedKeys = Object.keys(payload)
        .filter(key => key.toLowerCase().startsWith('pp') && key.toLowerCase() !== 'pp_securehash')
        .sort();

    // 2. Concatenate all non-empty values with '&'
    let valueStr = '';
    for (const key of sortedKeys) {
        const val = payload[key];
        if (val !== undefined && val !== null && val !== '') {
            valueStr += '&' + val;
        }
    }

    // 3. Prepend the Integrity Salt
    const dataString = integritySalt + valueStr;
    console.log('[DEBUG] String to hash:', dataString);

    // 4. Calculate HMAC-SHA256 using the Integrity Salt as the secret key
    const hash = crypto
        .createHmac('sha256', integritySalt)
        .update(dataString, 'utf8')
        .digest('hex');

    return hash.toUpperCase();
}

// Endpoint: Generate payload, calculate secure hash, and render auto-submit form redirect
app.post('/checkout/redirect', (req, res) => {
    const { amount, paymentMethod, mobileNo, email, merchantId, password, integritySalt, portalUrl } = req.body;

    if (!merchantId || !password || !integritySalt) {
        return res.send(`
            <html>
                <head>
                    <title>Config Error</title>
                    <style>
                        body { background: #121212; color: #ff5252; font-family: sans-serif; text-align: center; padding-top: 100px; }
                        a { color: #00e5ff; text-decoration: none; font-weight: bold; border: 1px solid #00e5ff; padding: 10px 20px; border-radius: 5px; margin-top: 20px; display: inline-block; }
                    </style>
                </head>
                <body>
                    <h2>JazzCash Credentials Missing!</h2>
                    <p>Please configure your Merchant ID, Password, and Integrity Salt before testing payments.</p>
                    <a href="/config.html">Configure Credentials Now</a>
                </body>
            </html>
        `);
    }

    // Amount needs to be in Paisa (multiplied by 100, no decimals)
    const amountInPaisa = Math.round(parseFloat(amount) * 100).toString();

    // Date formatting helper: yyyyMMddHHmmss (forces Pakistan standard timezone: Asia/Karachi)
    const formatDateTime = (date) => {
        const options = {
            timeZone: 'Asia/Karachi',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        };
        const formatter = new Intl.DateTimeFormat('en-US', options);
        const parts = formatter.formatToParts(date);
        const getPart = (type) => parts.find(p => p.type === type).value;
        
        const yyyy = getPart('year');
        const MM = getPart('month');
        const dd = getPart('day');
        const HH = getPart('hour');
        const mm = getPart('minute');
        const ss = getPart('second');

        const HH_fixed = HH === '24' ? '00' : HH;
        return `${yyyy}${MM}${dd}${HH_fixed}${mm}${ss}`;
    };

    const now = new Date();
    const expiry = new Date(now.getTime() + 2 * 60 * 60 * 1000); // 2 hours expiry

    const txnDateTime = formatDateTime(now);
    const txnExpiryDateTime = formatDateTime(expiry);
    const txnRefNo = 'T' + txnDateTime + Math.floor(100 + Math.random() * 900); // Unique Ref

    // Determine host protocol and address dynamically (Vercel uses HTTPS, local uses HTTP)
    const host = req.get('host');
    const protocol = host.startsWith('localhost') ? 'http' : 'https';
    const returnUrl = `${protocol}://${host}/payment/callback`;
    const targetPortalUrl = portalUrl || 'https://sandbox.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform';

    // 1. Common Payload Fields
    const payload = {
        pp_Version: paymentMethod === 'MPAY' ? '2.0' : '1.1',
        pp_TxnType: paymentMethod, // MWALLET, MPAY, or OTC
        pp_Language: 'EN',
        pp_MerchantID: merchantId,
        pp_Password: password,
        pp_TxnRefNo: txnRefNo,
        pp_Amount: amountInPaisa,
        pp_TxnCurrency: 'PKR',
        pp_TxnDateTime: txnDateTime,
        pp_BillReference: 'BILL' + txnDateTime.substring(8),
        pp_Description: 'SandboxPayment',
        pp_TxnExpiryDateTime: txnExpiryDateTime,
        pp_ReturnURL: returnUrl,
        pp_SubMerchantID: '',
        ppmpf_1: integritySalt, // Store the salt here dynamically to keep the returnUrl query-free
        ppmpf_2: '2',
        ppmpf_3: '3',
        ppmpf_4: '4',
        ppmpf_5: '5',
        pp_SecureHash: ''
    };

    // 2. Add Type-Specific Fields
    if (paymentMethod === 'MWALLET' || paymentMethod === 'OTC') {
        payload.pp_BankID = 'TBANK';
        payload.pp_ProductID = 'RETL';
    } else if (paymentMethod === 'MPAY') {
        payload.pp_BankID = '';
        payload.pp_ProductID = '';
        payload.pp_IsRegisteredCustomer = 'Yes';
        payload.pp_TokenizedCardNumber = '';
        payload.pp_CustomerID = 'Test';
        payload.pp_CustomerEmail = email || 'guest@novagear.com';
        payload.pp_CustomerMobile = mobileNo || '0343456789';
    }

    // 3. Generate Secure Hash
    payload.pp_SecureHash = generateSecureHash(payload, integritySalt);

    console.log('[DEBUG] Form redirect payload:', payload);

    // 4. Render Auto-Submit Form Redirection
    let formInputs = '';
    for (const [key, value] of Object.entries(payload)) {
        formInputs += `<input type="hidden" name="${key}" value="${value}">\n`;
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting to JazzCash...</title>
            <style>
                body {
                    background: #111115;
                    color: #fff;
                    font-family: 'Segoe UI', Roboto, sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                }
                .loader {
                    border: 4px solid #222;
                    border-top: 4px solid #c4151c;
                    border-radius: 50%;
                    width: 50px;
                    height: 50px;
                    animation: spin 1s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        </head>
        <body>
            <div class="loader"></div>
            <h2>Redirecting to JazzCash Secure Portal...</h2>
            <p>Please do not close this window or refresh the page.</p>

            <form name="jsform" method="post" action="${targetPortalUrl}">
                ${formInputs}
            </form>

            <script>
                document.jsform.submit();
            </script>
        </body>
        </html>
    `);
});

// Endpoint: Callback POST handler from JazzCash Page Redirection
app.post('/payment/callback', (req, res) => {
    const responsePayload = req.body;
    console.log('[DEBUG] Callback response payload:', responsePayload);

    const salt = responsePayload.ppmpf_1; // Retrieve salt from returned merchant play field
    const receivedHash = responsePayload.pp_SecureHash;

    // Check signature validity
    let hashVerified = false;
    let computedHash = '';
    if (salt && receivedHash) {
        computedHash = generateSecureHash(responsePayload, salt);
        hashVerified = (computedHash === receivedHash.toUpperCase());
    }

    const code = responsePayload.pp_ResponseCode || '';
    const msg = responsePayload.pp_ResponseMessage || '';
    const rrn = responsePayload.pp_RetreivalReferenceNo || '';
    const amount = responsePayload.pp_Amount || '';
    const txnRef = responsePayload.pp_TxnRefNo || '';
    const type = responsePayload.pp_TxnType || '';
    const status = (code === '000' && hashVerified) ? 'SUCCESS' : 'FAILED';

    // Build redirect query params for the client side to retrieve transaction details statelessly
    const queryParams = new URLSearchParams({
        status,
        code,
        msg,
        rrn,
        amount,
        txnRef,
        type,
        receivedHash: receivedHash || '',
        computedHash,
        verified: hashVerified.toString()
    });

    res.redirect(`/callback.html?${queryParams.toString()}`);
});

app.listen(PORT, () => {
    console.log(`==================================================`);
    console.log(`JazzCash Sandbox Store running on http://localhost:${PORT}`);
    console.log(`==================================================`);
});
