import express from 'express';
import crypto from 'crypto';
import { createCipheriv } from 'crypto';

const app = express();
app.use(express.json());

app.post('/encrypt', (req, res) => {
    const { password, v1, v2 } = req.body;
    
    if (!password || !v1 || !v2) {
        return res.status(400).send("Missing parameters: password, v1, v2 are required.");
    }
    
    // Step 1: MD5 hash of the password
    const md5Password = crypto.createHash('md5').update(password).digest('hex');
    
    // Step 2: Generate SHA-256 key
    const intermediateHash = crypto.createHash('sha256').update(md5Password + v1).digest('hex');
    const finalKey = crypto.createHash('sha256').update(intermediateHash + v2).digest();
    
    // Step 3: AES-ECB Encryption (No Padding)
    const cipher = createCipheriv('aes-256-ecb', finalKey, null);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(md5Password, 'hex')), cipher.final()]);
    
    res.send(encrypted.toString('hex'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Encryption server running on port ${PORT}`);
});
