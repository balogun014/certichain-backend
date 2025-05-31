const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { ethers } = require('ethers');
const pinataSDK = require('@pinata/sdk');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:8080'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database configuration
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Test database connection
(async () => {
  try {
    const client = await pool.connect();
    const res = await client.query('SELECT NOW()');
    console.log('Database connected:', res.rows[0]);
    client.release();
  } catch (err) {
    console.error('Database connection error:', err.stack);
    process.exit(1);
  }
})();

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Pinata configuration
const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET);

// Ethereum configuration
const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contractAddress = process.env.CONTRACT_ADDRESS;
const contractABI = [
  {
    "inputs": [
      { "internalType": "string", "name": "_id", "type": "string" },
      { "internalType": "address", "name": "_recipient", "type": "address" },
      { "internalType": "string", "name": "_metadata", "type": "string" }
    ],
    "name": "issueCertificate",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      { "internalType": "string", "name": "_id", "type": "string" }
    ],
    "name": "verifyCertificate",
    "outputs": [
      {
        "components": [
          { "internalType": "string", "name": "id", "type": "string" },
          { "internalType": "address", "name": "recipient", "type": "address" },
          { "internalType": "string", "name": "metadata", "type": "string" },
          { "internalType": "bool", "name": "isValid", "type": "bool" },
          { "internalType": "uint256", "name": "issuedAt", "type": "uint256" }
        ],
        "internalType": "struct CertiChain.Certificate",
        "name": "",
        "type": "tuple"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      { "internalType": "string", "name": "_id", "type": "string" }
    ],
    "name": "revokeCertificate",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
];
const contract = new ethers.Contract(contractAddress, contractABI, wallet);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Middleware to restrict to admins
const restrictToAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes
app.post('/signup', async (req, res) => {
  try {
    const { email, password, isAdmin } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, is_admin) VALUES ($1, $2, $3) RETURNING id, email, is_admin',
      [email, hashedPassword, isAdmin || false]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token, user });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create account' });
    }
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, email: user.email, isAdmin: user.is_admin } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/issue', authenticateToken, upload.single('logo'), async (req, res) => {
  try {
    const { studentName, course, dateIssued, recipientEmail, organization } = req.body;
    if (!studentName || !course || !dateIssued || !recipientEmail || !organization) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const metadata = {
      studentName,
      course,
      dateIssued,
      recipientEmail,
      organization,
      logoUrl: ''
    };

    if (req.file) {
      const pinataResponse = await pinata.pinFileToIPFS(req.file.buffer, {
        pinataMetadata: { name: `${studentName}-${course}-logo` },
        pinataOptions: { cidVersion: 0 }
      });
      metadata.logoUrl = `https://gateway.pinata.cloud/ipfs/${pinataResponse.IpfsHash}`;
    }

    const pinataResponse = await pinata.pinJSONToIPFS(metadata, {
      pinataMetadata: { name: `${studentName}-${course}-metadata` },
      pinataOptions: { cidVersion: 0 }
    });
    const ipfsHash = pinataResponse.IpfsHash;

    const certificateId = crypto.createHash('sha256')
      .update(JSON.stringify(metadata))
      .digest('hex');

    // Use recipient address (for now, use wallet address; adjust as needed)
    const recipientAddress = '0xE2761836f6fDb197Ad6600DF7C35eC4C373df1a0'; // TODO: Get from frontend or user input

    // Test gas estimation
    try {
      const gasEstimate = await contract.issueCertificate.estimateGas(certificateId, recipientAddress, ipfsHash);
      console.log('Gas estimate:', gasEstimate.toString());
    } catch (gasError) {
      throw new Error(`Gas estimation failed: ${gasError.message}`);
    }

    // Execute transaction
    const tx = await contract.issueCertificate(certificateId, recipientAddress, ipfsHash, {
      gasLimit: 300000
    });
    const receipt = await tx.wait();
    console.log('Transaction receipt:', receipt);

    await pool.query(
      'INSERT INTO certificates (id, student_name, course, date_issued, recipient_email, organization, ipfs_hash, tx_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [certificateId, studentName, course, dateIssued, recipientEmail, organization, ipfsHash, tx.hash]
    );

    res.json({ certificateId, txHash: tx.hash, ipfsHash });
  } catch (error) {
    console.error('Issue error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to issue certificate', details: error.message });
  }
});

app.post('/verify', async (req, res) => {
  console.log('Verify request body:', req.body);
  try {
    const { certificateHash } = req.body;
    if (!certificateHash) {
      return res.status(400).json({ error: 'Certificate hash is required' });
    }
    console.log('Calling contract.verifyCertificate with:', certificateHash);
    const cert = await contract.verifyCertificate(certificateHash);
    console.log('Contract response:', {
      id: cert.id,
      recipient: cert.recipient,
      metadata: cert.metadata,
      isValid: cert.isValid,
      issuedAt: cert.issuedAt.toString()
    });
    if (cert.issuedAt == 0) {
      return res.status(404).json({ isValid: false, error: 'Certificate not found' });
    }
    console.log('Querying database for certificate:', certificateHash);
    const result = await pool.query('SELECT * FROM certificates WHERE id = $1', [certificateHash]);
    const certificate = result.rows[0];
    console.log('Database response:', certificate);
    if (!certificate) {
      return res.status(404).json({ isValid: false, error: 'Certificate not found in database' });
    }
    res.json({
      isValid: cert.isValid,
      id: certificate.id,
      metadata: {
        studentName: certificate.student_name,
        course: certificate.course,
        dateIssued: certificate.date_issued,
        recipientEmail: certificate.recipient_email,
        organization: certificate.organization,
        logoUrl: certificate.logo_url || ''
      },
      recipient: cert.recipient,
      issuedAt: cert.issuedAt.toString()
    });
  } catch (error) {
    console.error('Verify error:', error.message, error.stack);
    res.status(500).json({ isValid: false, error: 'Failed to verify certificate', details: error.message });
  }
});

app.get('/certificates', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM certificates');
    res.json(result.rows);
  } catch (error) {
    console.error('Certificates error:', error);
    res.status(500).json({ error: 'Failed to fetch certificates' });
  }
});

app.get('/users', authenticateToken, restrictToAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, is_admin FROM users');
    res.json(result.rows);
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});