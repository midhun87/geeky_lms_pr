require('dotenv').config();
const express = require('express');
const cors = require('cors');
const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto'); // Added for secure OTP generation

const app = express();
app.use(cors());
app.use(express.json({ limit: '1500mb' }));
app.use(express.urlencoded({ extended: true, limit: '1500mb' }));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_here_2026';

/* ==========================================================================
   AWS CONFIGURATION & SERVICES
   ========================================================================== */
AWS.config.update({
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const dynamoDB = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

const sesConfig = {
    region: process.env.SES_AWS_REGION || process.env.AWS_REGION,
    accessKeyId: process.env.SES_AWS_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.SES_AWS_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY
};
const ses = new AWS.SES(sesConfig);

// Table Names
const TABLE_USERS = process.env.TABLE_USERS || 'Geeky_Users';
const TABLE_LEVELS = process.env.TABLE_LEVELS || 'Geeky_Levels';
const TABLE_CONTENT = process.env.TABLE_CONTENT || 'Geeky_Content';
const TABLE_RECORDINGS = process.env.TABLE_RECORDINGS || 'Geeky_Recordings';
const TABLE_TESTS = process.env.TABLE_TESTS || 'Geeky_Tests';
const TABLE_SCORES = process.env.TABLE_SCORES || 'Geeky_TestScores';
const TABLE_PROGRESS = process.env.TABLE_PROGRESS || 'Geeky_Progress'; 
const TABLE_TOKENS = process.env.TABLE_TOKENS || 'Geeky_Tokens'; 

const SES_SOURCE_EMAIL = process.env.SES_SOURCE_EMAIL || 'admin@geekyresearcher.com';
const S3_BUCKET = process.env.S3_BUCKET_NAME || 'geeky-researcher-assets';

/* ==========================================================================
   MIDDLEWARE
   ========================================================================== */
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied, token missing. Please log in again.' });

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        
        // Single Device Login Check: Fetch user to verify active session
        const userRes = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email: decoded.email } }).promise();
        const user = userRes.Item;

        if (!user) return res.status(404).json({ error: 'User not found.' });

        // If the DB has an active session ID but it doesn't match the one in the token, reject request
        if (user.activeSessionId && user.activeSessionId !== decoded.sessionId) {
            return res.status(401).json({ 
                error: 'SESSION_CONFLICT', 
                message: 'You have been logged out because your account was accessed from another device.' 
            });
        }

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Admin privileges required to perform this action.' });
    }
};

/* ==========================================================================
   HELPER FUNCTIONS
   ========================================================================== */
async function deleteS3ObjectSafely(s3Key) {
    if (!s3Key) return;
    try {
        await s3.deleteObject({ Bucket: S3_BUCKET, Key: s3Key }).promise();
        console.log(`Deleted S3 Object: ${s3Key}`);
    } catch (error) {
        console.error(`Failed to delete S3 Object ${s3Key}:`, error.message);
    }
}

async function sendEmailSafely(to, subject, htmlBody) {
    try {
        console.log(`Attempting to send email via SES to ${to} from ${SES_SOURCE_EMAIL}...`);
        await ses.sendEmail({
            Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
            Message: { 
                Body: { Html: { Data: htmlBody } }, 
                Subject: { Data: subject } 
            },
            Source: SES_SOURCE_EMAIL
        }).promise();
        console.log(`Email successfully sent to ${to}`);
    } catch (error) {
        console.error(`Failed to send email via SES to ${to}:`, error);
        // Important: We don't want to swallow this error if the email fails,
        // otherwise the user gets stuck thinking an email is coming.
        throw new Error(`Email delivery failed: ${error.message}`);
    }
}

// Ensure the Tokens table exists or create it safely for OTPs
async function ensureTokensTableExists() {
    const dynamodbService = new AWS.DynamoDB();
    try {
        await dynamodbService.describeTable({ TableName: TABLE_TOKENS }).promise();
        console.log(`[DynamoDB] Table '${TABLE_TOKENS}' already exists.`);
    } catch (error) {
        if (error.code === 'ResourceNotFoundException') {
            console.log(`[DynamoDB] Table '${TABLE_TOKENS}' not found. Attempting to create it automatically...`);
            
            const params = {
                TableName: TABLE_TOKENS,
                KeySchema: [
                    { AttributeName: 'email', KeyType: 'HASH' }
                ],
                AttributeDefinitions: [
                    { AttributeName: 'email', AttributeType: 'S' }
                ],
                BillingMode: 'PAY_PER_REQUEST'
            };

            try {
                await dynamodbService.createTable(params).promise();
                console.log(`[DynamoDB] Successfully issued create command for table '${TABLE_TOKENS}'.`);
                // Note: It takes a few moments for AWS to provision the table. 
                // We'll wait a bit just to be safe if someone tries to register immediately.
                await dynamodbService.waitFor('tableExists', { TableName: TABLE_TOKENS }).promise();
                console.log(`[DynamoDB] Table '${TABLE_TOKENS}' is now ACTIVE and ready for use.`);
            } catch (createError) {
                console.error(`[DynamoDB] Failed to create table '${TABLE_TOKENS}':`, createError);
            }
        } else {
            console.error(`[DynamoDB] Error checking for table '${TABLE_TOKENS}':`, error);
        }
    }
}

// Check on startup
ensureTokensTableExists();


/* ==========================================================================
   OTP & AUTHENTICATION ROUTES
   ========================================================================== */

// Unified OTP Sender for Registration and Password Resets
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { email, type } = req.body; 
        if (!email || !type) return res.status(400).json({ error: 'Email and type are required.' });

        console.log(`Initiating OTP send for email: ${email}, type: ${type}`);

        let existingUser = null;
        try {
            const userCheck = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
            existingUser = userCheck.Item;
        } catch (dbError) {
             console.error("Error checking Users table:", dbError);
             if (dbError.code === 'ResourceNotFoundException') {
                 return res.status(500).json({ error: `Database configuration error: Table '${TABLE_USERS}' not found.` });
             }
             throw dbError;
        }

        if (type === 'register' && existingUser) {
            return res.status(400).json({ error: 'An account with this email already exists.' });
        }
        if (type === 'reset' && !existingUser) {
            return res.status(404).json({ error: 'No account found with this email.' });
        }

        // Generate a 6-digit OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

        try {
            console.log(`Saving OTP to table: ${TABLE_TOKENS}`);
            await dynamoDB.put({
                TableName: TABLE_TOKENS,
                Item: { email, otp, expiresAt, type }
            }).promise();
        } catch (dbError) {
            console.error(`Error writing to ${TABLE_TOKENS}:`, dbError);
            if (dbError.code === 'ResourceNotFoundException') {
                 return res.status(500).json({ 
                     error: `Database configuration error: Table '${TABLE_TOKENS}' not found. Please create this table in AWS DynamoDB with 'email' as the Primary Partition Key (String).` 
                 });
            }
            throw dbError;
        }

        const subject = type === 'register' ? 'Verify your Registration - Geeky Researcher' : 'Password Reset Request - Geeky Researcher';
        const htmlBody = `
            <div style="background-color: #f1f5f9; padding: 60px 20px; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #334155;">

    <div style="max-width: 520px; margin: 0 auto; background-color: #ffffff; border-radius: 24px; box-shadow: 0 10px 40px -10px rgba(0,0,0,0.08); overflow: hidden; border: 1px solid #e2e8f0;">

        <!-- Tech/Premium Gradient Accent Bar -->
        <div style="height: 6px; background: linear-gradient(90deg, #3b82f6, #8b5cf6);"></div>

        <div style="padding: 48px 40px;">

            <!-- Header & Logo -->
            <div style="text-align: center; margin-bottom: 32px;">
                <div style="display: inline-block; padding: 4px; border: 1px solid #e2e8f0; border-radius: 18px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <img 
                        src="https://res.cloudinary.com/dzuxwvamy/image/upload/v1783935221/WhatsApp_Image_2026-07-08_at_6.25.14_PM_aiuvde.jpg" 
                        alt="Geeky Researcher Logo" 
                        style="width: 64px; height: 64px; border-radius: 14px; display: block; object-fit: cover;"
                    >
                </div>
                <h2 style="margin: 0; color: #0f172a; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">
                    ${subject}
                </h2>
            </div>

            <!-- Body Content -->
            <p style="margin: 0 0 16px; color: #0f172a; font-size: 16px; font-weight: 600;">
                Welcome to Geeky Researcher!
            </p>
            <p style="margin: 0 0 32px; color: #475569; font-size: 15px; line-height: 1.7;">
                Thank you for starting your registration with the <strong>Geeky Researcher portal</strong>. You are just one step away. Please use the One-Time Password (OTP) below to verify your email address and complete your account setup.
            </p>

            <!-- OTP Highlight Box -->
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 32px 20px; text-align: center; margin-bottom: 32px;">
                <p style="margin: 0 0 12px; color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1.5px;">
                    Your Verification Code
                </p>
                <div style="color: #0f172a; font-size: 42px; font-weight: 700; letter-spacing: 16px; font-family: 'Courier New', Courier, monospace; margin-left: 16px;">
                    ${otp}
                </div>
            </div>

            <!-- Subtle Security Note -->
            <div style="text-align: center; margin-bottom: 40px;">
                <p style="margin: 0; color: #64748b; font-size: 13px; line-height: 1.5;">
                    This code will expire in <strong>10 minutes</strong>.<br>
                    If you did not request this registration, please safely ignore this email.
                </p>
            </div>

            <!-- Divider -->
            <div style="height: 1px; background-color: #e2e8f0; margin: 0 0 24px;"></div>

            <!-- Footer -->
            <div style="text-align: center;">
                <p style="margin: 0 0 12px; color: #94a3b8; font-size: 12px; font-weight: 500;">
                    Secured & Developed by
                </p>
                
                <a href="https://www.xetatechsolutions.com/" target="_blank" style="text-decoration: none; display: inline-block; transition: opacity 0.2s;">
                    <img 
                        src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_LOGO_bcsbwh.png" 
                        alt="Xeta Tech Solutions" 
                        style="width: 44px; height: auto; display: inline-block; filter: grayscale(100%) opacity(70%);"
                    >
                </a>
                
                <p style="margin: 8px 0 0; font-size: 12px;">
                    <a href="https://www.xetatechsolutions.com/" target="_blank" style="color: #94a3b8; text-decoration: none; font-weight: 500;">
                        xetatechsolutions.com
                    </a>
                </p>
            </div>

        </div>
    </div>
</div>
        `;

        // Send email and catch SES specific errors
        try {
             await sendEmailSafely(email, subject, htmlBody);
        } catch (sesError) {
             return res.status(500).json({ error: sesError.message });
        }

        res.json({ message: 'OTP sent successfully to your email.' });
    } catch (error) {
        console.error("OTP Send Overall Error:", error);
        res.status(500).json({ error: 'Failed to process OTP request. Please check server logs.' });
    }
});

// Handle Password Reset
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields are required.' });

        const tokenData = await dynamoDB.get({ TableName: TABLE_TOKENS, Key: { email } }).promise();
        
        if (!tokenData.Item || tokenData.Item.otp !== otp || tokenData.Item.type !== 'reset') {
            return res.status(400).json({ error: 'Invalid or incorrect OTP.' });
        }
        if (Date.now() > tokenData.Item.expiresAt) {
            return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'set password = :p',
            ExpressionAttributeValues: { ':p': hashedPassword }
        }).promise();

        // Cleanup used OTP
        await dynamoDB.delete({ TableName: TABLE_TOKENS, Key: { email } }).promise();

        res.json({ message: 'Password has been reset successfully. You can now log in.' });
    } catch (error) {
        console.error("Password Reset Error:", error);
        res.status(500).json({ error: 'Failed to reset password.' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, mobile, organization, level, password, paymentPlan, otp } = req.body;
        if (!name || !email || !password || !level || !otp) {
            return res.status(400).json({ error: 'Missing required fields (Name, Email, Password, Level, OTP)' });
        }

        // 1. Verify OTP
        const tokenRecord = await dynamoDB.get({ TableName: TABLE_TOKENS, Key: { email } }).promise();
        if (!tokenRecord.Item || tokenRecord.Item.otp !== otp || tokenRecord.Item.type !== 'register') {
            return res.status(400).json({ error: 'Invalid or missing OTP.' });
        }
        if (new Date() > new Date(tokenRecord.Item.expiresAt)) {
            return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
        }

        // 2. Check existing user
        const existingUser = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        if (existingUser.Item) return res.status(400).json({ error: 'An account with this email already exists.' });

        // 3. Create User
        const hashedPassword = await bcrypt.hash(password, 10);
        const selectedPlan = paymentPlan || '100'; 
        
        const newUser = {
            email, name, mobile: mobile || '', organization: organization || '', level,
            password: hashedPassword,
            role: 'student',
            status: 'pending_initial',
            paymentPlan: selectedPlan,
            createdAt: new Date().toISOString()
        };

        await dynamoDB.put({ TableName: TABLE_USERS, Item: newUser }).promise();
        
        // 4. Delete used OTP
        await dynamoDB.delete({ TableName: TABLE_TOKENS, Key: { email } }).promise();

        // 5. Notify Admin via Email to researchergeeky@gmail.com
        await sendEmailSafely(
            'researchergeeky@gmail.com', 
            'Action Required: New Registration Pending Approval',
            `<div style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #0f172a;">New Registration Alert</h2>
                <p>A new student has registered and is awaiting payment verification and approval.</p>
                <div style="background-color: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <p style="margin: 5px 0;"><strong>Name:</strong> ${name}</p>
                    <p style="margin: 5px 0;"><strong>Email:</strong> ${email}</p>
                    <p style="margin: 5px 0;"><strong>Mobile:</strong> ${mobile || 'N/A'}</p>
                    <p style="margin: 5px 0;"><strong>Institute:</strong> ${organization || 'N/A'}</p>
                    <p style="margin: 5px 0;"><strong>Level:</strong> ${level}</p>
                    <p style="margin: 5px 0;"><strong>Payment Plan:</strong> ${selectedPlan}%</p>
                </div>
                <p style="margin-top: 15px;">Please log in to your admin dashboard to verify their payment and approve access.</p>
            </div>`
        );

        // 6. Notify Student via Email
        await sendEmailSafely(
            email,
            'Registration Pending - Geeky Researcher',
            `<h2>Registration Received</h2>
             <p>Hi ${name},</p>
             <p>Your registration for <strong>${level}</strong> (${selectedPlan}% payment plan) has been received.</p>
             <p>You will be notified via email once the administrator approves your access. Thank you for joining!</p>`
        );

        res.status(201).json({ message: 'Registration successful', user: { email, name, status: 'pending_initial' } });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: 'Registration failed due to a server error.' });
    }
});
app.post('/api/auth/login', async (req, res) => {
    try {
        // Now accepting deviceName and forceLogin
        const { email, password, role, deviceName, forceLogin } = req.body;
        if(!email || !password) return res.status(400).json({ error: 'Email and password required.' });

        const result = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        const user = result.Item;

        if (!user || user.role !== role) return res.status(401).json({ error: 'Invalid credentials or role mismatch.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials.' });

        if (user.status === 'blocked') {
            return res.status(403).json({ error: 'Your access has been revoked by an administrator.' });
        }

        if (user.role === 'student' && user.status !== 'approved' && user.status !== 'pending_upgrade') {
            return res.status(403).json({ error: 'Account pending verification. Please wait for admin approval.' });
        }

        if (user.role === 'student' && user.accessExpiresAt) {
            if (new Date() > new Date(user.accessExpiresAt)) {
                return res.status(403).json({ error: 'Your access duration has expired. Please upgrade your plan.' });
            }
        }

        // --- SINGLE DEVICE LOGIN LOGIC (Admins bypass this check) ---
        // If an active session exists, user is a student, and user hasn't explicitly clicked "logout other device"
        if (user.role !== 'admin' && user.activeSessionId && !forceLogin) {
            return res.status(409).json({
                error: 'ACTIVE_SESSION',
                message: 'You are already logged in on another device.',
                activeDeviceName: user.activeDeviceName || 'Unknown Device'
            });
        }

        // Generate new session ID
        const sessionId = uuidv4();
        const currentDeviceName = deviceName || req.headers['user-agent'] || 'Unknown Device';

        // Update DB with the new active session ID and device name
        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'set activeSessionId = :sid, activeDeviceName = :dn',
            ExpressionAttributeValues: {
                ':sid': sessionId,
                ':dn': currentDeviceName
            }
        }).promise();
        // ---------------------------------

        // Add sessionId to JWT Payload so the middleware can check it later
        const tokenPayload = { email: user.email, name: user.name, role: user.role, level: user.level, sessionId };
        const token = jwt.encode(tokenPayload, JWT_SECRET);

        res.json({ 
            message: 'Login successful', 
            token, 
            user: { 
                name: user.name, 
                role: user.role, 
                level: user.level, 
                email: user.email,
                paymentPlan: user.paymentPlan,
                accessExpiresAt: user.accessExpiresAt
            } 
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Login failed due to a server error.' });
    }
});
app.get('/api/auth/status', async (req, res) => {
    try {
        const { email } = req.query;
        if (!email) return res.status(400).json({ error: 'Email parameter is required.' });
        const result = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        if (!result.Item) return res.status(404).json({ error: 'User not found in the system.' });
        res.json({ status: result.Item.status, plan: result.Item.paymentPlan });
    } catch (error) {
        res.status(500).json({ error: 'Status check failed.' });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const { email } = req.user;
        
        // Remove the active session from DynamoDB to free up the login
        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'remove activeSessionId, activeDeviceName'
        }).promise();
        
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ error: 'Logout failed.' });
    }
});

/* ==========================================================================
   STUDENT PROFILE & PROGRESS ROUTES
   ========================================================================== */
app.get('/api/student/me', authenticateToken, async (req, res) => {
    try {
        const { email } = req.user;
        const result = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        if(!result.Item) return res.status(404).json({error: 'User profile not found.'});
        
        const { password, ...safeUser } = result.Item; 
        res.json(safeUser);
    } catch(err) {
        res.status(500).json({error: 'Failed to fetch student data.'});
    }
});

app.put('/api/student/profile', authenticateToken, async (req, res) => {
    try {
        const { email } = req.user;
        const { name, mobile, organization } = req.body;
        
        const updateParams = {
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'set #name = :n, mobile = :m, organization = :o',
            ExpressionAttributeNames: { '#name': 'name' },
            ExpressionAttributeValues: { ':n': name, ':m': mobile || '', ':o': organization || '' },
            ReturnValues: "UPDATED_NEW"
        };
        
        const result = await dynamoDB.update(updateParams).promise();
        res.json({ message: 'Profile updated successfully.', updatedAttributes: result.Attributes });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile.' });
    }
});

app.post('/api/student/upgrade-plan', authenticateToken, async (req, res) => {
    try {
        const { email, name } = req.user;
        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'set #status = :s',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { ':s': 'pending_upgrade' }
        }).promise();

        await sendEmailSafely(
            SES_SOURCE_EMAIL, 
            'Upgrade Request Received',
            `<p>Student <strong>${name}</strong> (${email}) has requested an account upgrade/extension.</p>`
        );

        res.json({ message: 'Upgrade request submitted. Awaiting admin approval.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process upgrade request.' });
    }
});

/* ==========================================================================
   ADMIN METRICS & USER MANAGEMENT
   ========================================================================== */
app.get('/api/admin/metrics', authenticateToken, isAdmin, async (req, res) => {
    try {
        const [users, levels, content, recordings, tests] = await Promise.all([
            dynamoDB.scan({ TableName: TABLE_USERS }).promise(),
            dynamoDB.scan({ TableName: TABLE_LEVELS }).promise(),
            dynamoDB.scan({ TableName: TABLE_CONTENT }).promise(),
            dynamoDB.scan({ TableName: TABLE_RECORDINGS }).promise(),
            dynamoDB.scan({ TableName: TABLE_TESTS }).promise()
        ]);

        const safeItems = (data) => data.Items || [];
        
        const pendingApprovals = safeItems(users).filter(u => ['pending_initial', 'pending', 'pending_upgrade'].includes(u.status)).length;
        const totalStudents = safeItems(users).filter(u => u.role === 'student' && u.status === 'approved').length;
        const blockedStudents = safeItems(users).filter(u => u.role === 'student' && u.status === 'blocked').length;

        let estRevenue = 0;
        const levelFeeMap = {};
        safeItems(levels).forEach(l => { levelFeeMap[l.levelName] = parseFloat(l.fee) || 0; });
        
        safeItems(users).forEach(u => {
            if (u.role === 'student' && u.status === 'approved') {
                const baseFee = levelFeeMap[u.level] || 0;
                const planPercent = parseInt(u.paymentPlan) || 100;
                estRevenue += (baseFee * planPercent) / 100;
            }
        });

        res.json({ 
            totalStudents, pendingApprovals, blockedStudents,
            activeLevels: safeItems(levels).length, 
            contentAssets: safeItems(content).length,
            recordedAssets: safeItems(recordings).length,
            assessments: safeItems(tests).length,
            estimatedRevenue: estRevenue
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch system metrics.' });
    }
});

app.get('/api/admin/pending-approvals', authenticateToken, isAdmin, async (req, res) => {
    try {
        const params = {
            TableName: TABLE_USERS,
            FilterExpression: '#status IN (:s1, :s2, :s3)',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { ':s1': 'pending_initial', ':s2': 'pending_upgrade', ':s3': 'pending' }
        };
        const result = await dynamoDB.scan(params).promise();
        res.json((result.Items || []).map(u => ({ 
            name: u.name, email: u.email, level: u.level, mobile: u.mobile, 
            organization: u.organization, status: u.status, paymentPlan: u.paymentPlan,
            createdAt: u.createdAt,
            accessExpiresAt: u.accessExpiresAt,
            accessStartsAt: u.accessStartsAt // Ensure start date is returned for correct upgrade calculations
        })));
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch pending approvals.' });
    }
});

app.get('/api/admin/students-directory', authenticateToken, isAdmin, async (req, res) => {
    try {
        const [usersData, levelsData] = await Promise.all([
            dynamoDB.scan({ TableName: TABLE_USERS }).promise(),
            dynamoDB.scan({ TableName: TABLE_LEVELS }).promise()
        ]);

        const levelFees = {};
        (levelsData.Items || []).forEach(l => { levelFees[l.levelName] = parseFloat(l.fee) || 0; });

        const students = (usersData.Items || [])
            .filter(u => u.role === 'student')
            .map(student => {
                const baseFee = levelFees[student.level] || 0;
                const planPercent = parseInt(student.paymentPlan) || 100;
                let currentStatus = student.status;
                if (currentStatus === 'approved' && student.accessExpiresAt) {
                    if (new Date() > new Date(student.accessExpiresAt)) currentStatus = 'expired';
                }

                return {
                    name: student.name, email: student.email, mobile: student.mobile,
                    organization: student.organization, level: student.level,
                    paymentPlan: student.paymentPlan || '100', status: currentStatus,
                    accessExpiresAt: student.accessExpiresAt, accessStartsAt: student.accessStartsAt,
                    amountPaid: (baseFee * planPercent) / 100, createdAt: student.createdAt
                };
            });

        students.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        res.json(students);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch students directory.' });
    }
});

app.post('/api/admin/approve-student', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        const userRes = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        const user = userRes.Item;
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        let totalDurationMonths = 6; 
        if (user.level) {
            const levelRes = await dynamoDB.get({ TableName: TABLE_LEVELS, Key: { levelName: user.level } }).promise();
            if (levelRes.Item && levelRes.Item.durationMonths) totalDurationMonths = parseInt(levelRes.Item.durationMonths);
        }

        // --- BUG FIX: Upgrade logic handling ---
        const isUpgrade = user.status === 'pending_upgrade';
        // Force 100% plan if it's an upgrade. Otherwise keep existing plan or default to 100.
        const currentPlan = isUpgrade ? '100' : (user.paymentPlan ? user.paymentPlan.toString() : '100');

        let planMultiplier = 1; let bufferDays = 0;
        if (currentPlan === '50') { planMultiplier = 0.5; bufferDays = 5; } 
        else if (currentPlan === '75') { planMultiplier = 0.75; bufferDays = 5; }

        // If upgrading, calculate expiry from the original access start date so they get full duration
        // If new registration, accessStartsAt becomes now.
        const accessStartsAt = (isUpgrade && user.accessStartsAt) ? new Date(user.accessStartsAt) : new Date();
        const accessExpiresAt = new Date(accessStartsAt);
        const addedMonths = totalDurationMonths * planMultiplier;
        
        accessExpiresAt.setMonth(accessExpiresAt.getMonth() + Math.floor(addedMonths));
        accessExpiresAt.setDate(accessExpiresAt.getDate() + Math.round((addedMonths - Math.floor(addedMonths)) * 30) + bufferDays);

        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            UpdateExpression: 'set #status = :s, accessStartsAt = :start, accessExpiresAt = :end, paymentPlan = :p',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { 
                ':s': 'approved', 
                ':start': accessStartsAt.toISOString(),
                ':end': accessExpiresAt.toISOString(), 
                ':p': currentPlan // Correctly saves '100' for upgrades
            }
        }).promise();

        await sendEmailSafely(
            email, 'Account Approved - Geeky Researcher',
            `<div style="background-color: #f1f5f9; padding: 60px 20px; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #334155;">

    <div style="max-width: 520px; margin: 0 auto; background-color: #ffffff; border-radius: 24px; box-shadow: 0 10px 40px -10px rgba(0,0,0,0.08); overflow: hidden; border: 1px solid #e2e8f0;">

        <!-- Tech/Premium Gradient Accent Bar -->
        <div style="height: 6px; background: linear-gradient(90deg, #3b82f6, #8b5cf6);"></div>

        <div style="padding: 48px 40px;">

            <!-- Header & Logo -->
            <div style="text-align: center; margin-bottom: 32px;">
                <div style="display: inline-block; padding: 4px; border: 1px solid #e2e8f0; border-radius: 18px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
                    <img 
                        src="https://res.cloudinary.com/dzuxwvamy/image/upload/v1783935221/WhatsApp_Image_2026-07-08_at_6.25.14_PM_aiuvde.jpg" 
                        alt="Geeky Researcher Logo" 
                        style="width: 64px; height: 64px; border-radius: 14px; display: block; object-fit: cover;"
                    >
                </div>
                <h2 style="margin: 0; color: #0f172a; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">
                    Welcome to Geeky Researcher!
                </h2>
            </div>

            <!-- Body Content -->
            <p style="margin: 0 0 28px; color: #475569; font-size: 15px; line-height: 1.7; text-align: center;">
                Great news! Your account has been <strong>fully approved</strong>. You are now ready to start exploring the modules and recorded classes.
            </p>

            <!-- Account Details Highlight Box -->
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 24px; margin-bottom: 32px;">
                
                <div style="margin-bottom: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 16px;">
                    <p style="margin: 0 0 4px; color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                        Enrolled Level
                    </p>
                    <p style="margin: 0; color: #0f172a; font-size: 18px; font-weight: 700;">
                        ${user.level}
                    </p>
                </div>

                <div>
                    <p style="margin: 0 0 4px; color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                        Access Valid Until
                    </p>
                    <p style="margin: 0; color: #0f172a; font-size: 16px; font-weight: 600;">
                        ${accessExpiresAt.toDateString()}
                    </p>
                </div>

            </div>

            <!-- Call to Action Button -->
            <div style="text-align: center; margin-bottom: 40px;">
                <a href="https://www.app.geekyresearcher.com/" target="_blank" style="display: inline-block; background-color: #3b82f6; color: #ffffff; font-size: 15px; font-weight: 600; text-decoration: none; padding: 14px 32px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.3);">
                    Log In to Dashboard
                </a>
            </div>

            <!-- Divider -->
            <div style="height: 1px; background-color: #e2e8f0; margin: 0 0 24px;"></div>

            <!-- Footer -->
            <div style="text-align: center;">
                <p style="margin: 0 0 12px; color: #94a3b8; font-size: 12px; font-weight: 500;">
                    Secured & Developed by
                </p>
                
                <a href="https://www.xetatechsolutions.com/" target="_blank" style="text-decoration: none; display: inline-block;">
                    <img 
                        src="https://res.cloudinary.com/dpz44zf0z/image/upload/v1760704788/XETA_SOLUTIONS_LOGO_bcsbwh.png" 
                        alt="Xeta Tech Solutions" 
                        style="width: 44px; height: auto; display: inline-block; filter: grayscale(100%) opacity(70%);"
                    >
                </a>
                
                <p style="margin: 8px 0 0; font-size: 12px;">
                    <a href="https://www.xetatechsolutions.com/" target="_blank" style="color: #94a3b8; text-decoration: none; font-weight: 500;">
                        xetatechsolutions.com
                    </a>
                </p>
            </div>

        </div>
    </div>
</div>`
        );

        res.json({ message: 'Student approved successfully', expiresAt: accessExpiresAt.toISOString() });
    } catch (error) {
        console.error("Approve student error:", error);
        res.status(500).json({ error: 'Failed to approve student.' });
    }
});

app.post('/api/admin/decline-student', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        const userRes = await dynamoDB.get({ TableName: TABLE_USERS, Key: { email } }).promise();
        
        if (userRes.Item && userRes.Item.status === 'pending_upgrade') {
            await dynamoDB.update({ 
                TableName: TABLE_USERS, Key: { email }, 
                UpdateExpression: 'set #status = :s', 
                ExpressionAttributeNames: { '#status': 'status' }, 
                ExpressionAttributeValues: { ':s': 'approved' } 
            }).promise();
            res.json({ message: 'Upgrade declined. Student reverted to standard approved status.' });
        } else {
            await dynamoDB.delete({ TableName: TABLE_USERS, Key: { email } }).promise();
            res.json({ message: 'Student application declined and record removed.' });
        }
    } catch (error) { res.status(500).json({ error: 'Failed to decline student.' }); }
});

app.post('/api/admin/block-student', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        await dynamoDB.update({ 
            TableName: TABLE_USERS, Key: { email }, 
            UpdateExpression: 'set #status = :s', 
            ExpressionAttributeNames: { '#status': 'status' }, 
            ExpressionAttributeValues: { ':s': 'blocked' } 
        }).promise();
        res.json({ message: 'Student access permanently revoked (Blocked).' });
    } catch (error) { res.status(500).json({ error: 'Failed to block student.' }); }
});

app.post('/api/admin/unblock-student', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        await dynamoDB.update({ 
            TableName: TABLE_USERS, Key: { email }, 
            UpdateExpression: 'set #status = :s', 
            ExpressionAttributeNames: { '#status': 'status' }, 
            ExpressionAttributeValues: { ':s': 'approved' } 
        }).promise();
        res.json({ message: 'Student access restored (Unblocked).' });
    } catch (error) { res.status(500).json({ error: 'Failed to unblock student.' }); }
});

app.post('/api/admin/extend-student', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { email, newExpiryDate } = req.body;
        if (!email || !newExpiryDate) return res.status(400).json({ error: 'Email and new expiry date are required.' });

        await dynamoDB.update({
            TableName: TABLE_USERS,
            Key: { email },
            // Reset status to 'approved' in case their account was previously marked as 'expired'
            UpdateExpression: 'set accessExpiresAt = :end, #status = :s', 
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { 
                ':end': new Date(newExpiryDate).toISOString(),
                ':s': 'approved'
            }
        }).promise();

        res.json({ message: 'Student access duration extended successfully.' });
    } catch (error) { res.status(500).json({ error: 'Failed to extend student duration.' }); }
});


app.delete('/api/admin/student/:email', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dynamoDB.delete({ TableName: TABLE_USERS, Key: { email: decodeURIComponent(req.params.email) } }).promise();
        res.json({ message: 'Student deleted entirely from the system.' });
    } catch (error) { res.status(500).json({ error: 'Failed to delete user.' }); }
});

app.post('/api/admin/levels/upload-url', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { fileName, fileType } = req.body;
        const fileKey = `qrcodes/${uuidv4()}-${fileName.replace(/[^a-zA-Z0-9.\-_]/g, '')}`;
        // 2. Extend expiration to 3 hours (10800 seconds) for slow connections
        const params = { Bucket: S3_BUCKET, Key: fileKey, Expires: 10800, ContentType: fileType };
        
        const uploadUrl = await s3.getSignedUrlPromise('putObject', params);
        const readUrl = `https://${S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
        
        res.json({ uploadUrl, s3Key: fileKey, readUrl });
    } catch (error) { 
        console.error("QR S3 Upload URL Error:", error);
        res.status(500).json({ error: 'Upload URL generation failed. Check AWS configuration.' }); 
    }
});

/* ==========================================================================
   ADMIN LEVELS MANAGEMENT
   ========================================================================== */
app.get('/api/admin/levels', async (req, res) => {
    try {
        const result = await dynamoDB.scan({ TableName: TABLE_LEVELS }).promise();
        let levels = result.Items || [];
        
        // Sign QR codes if they belong to our private S3 bucket
        const bucketPrefix = `https://${S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/`;
        
        levels = await Promise.all(levels.map(async (lvl) => {
            if (lvl.qrCodeUrl && lvl.qrCodeUrl.startsWith(bucketPrefix)) {
                try {
                    // Extract the raw S3 Key from the URL and sign it for 1 hour
                    const s3Key = lvl.qrCodeUrl.replace(bucketPrefix, '');
                    const urlParams = { Bucket: S3_BUCKET, Key: decodeURIComponent(s3Key), Expires: 3600 };
                    lvl.qrCodeUrl = await s3.getSignedUrlPromise('getObject', urlParams);
                } catch (err) {
                    console.error("Failed to sign QR URL for level:", lvl.levelName, err);
                }
            }
            return lvl;
        }));

        res.json(levels);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch levels' }); }
});

app.post('/api/admin/levels', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, fee, durationMonths, qrCodeUrl, description } = req.body;
        if (!name) return res.status(400).json({ error: 'Level name required' });
        
        await dynamoDB.put({ 
            TableName: TABLE_LEVELS, 
            Item: { 
                levelName: name, 
                fee: fee || 0,
                durationMonths: durationMonths || 6,
                qrCodeUrl: qrCodeUrl || '',
                description: description || '',
                createdAt: new Date().toISOString() 
            } 
        }).promise();
        res.status(201).json({ message: 'Level added successfully.' });
    } catch (error) { res.status(500).json({ error: 'Failed to add level' }); }
});

app.delete('/api/admin/levels/:name', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dynamoDB.delete({ TableName: TABLE_LEVELS, Key: { levelName: decodeURIComponent(req.params.name) } }).promise();
        res.json({ message: 'Level deleted successfully.' });
    } catch (error) { res.status(500).json({ error: 'Failed to delete level' }); }
});
app.put('/api/admin/levels/:name', authenticateToken, isAdmin, async (req, res) => {
    try {
        const levelName = decodeURIComponent(req.params.name);
        const { fee, durationMonths, qrCodeUrl } = req.body;
        
        // Fetch existing level first to ensure it exists and clean up old QR code if updated
        const existing = await dynamoDB.get({ TableName: TABLE_LEVELS, Key: { levelName } }).promise();
        if (!existing.Item) return res.status(404).json({ error: 'Level not found' });

        let updateExpression = 'set fee = :f, durationMonths = :d';
        let expressionAttributeValues = {
            ':f': fee !== undefined ? fee : existing.Item.fee,
            ':d': durationMonths !== undefined ? durationMonths : existing.Item.durationMonths
        };

        // If a new QR code is provided, update it and attempt to delete the old one from S3
        if (qrCodeUrl) {
            updateExpression += ', qrCodeUrl = :q';
            expressionAttributeValues[':q'] = qrCodeUrl;
            
            // Cleanup the old S3 object safely using its prefix
            if (existing.Item.qrCodeUrl) {
                try {
                    const bucketPrefix = `https://${process.env.S3_BUCKET_NAME || 'geeky-researcher-assets'}.s3.${process.env.AWS_REGION}.amazonaws.com/`;
                    if (existing.Item.qrCodeUrl.startsWith(bucketPrefix)) {
                        const oldS3Key = decodeURIComponent(existing.Item.qrCodeUrl.replace(bucketPrefix, ''));
                        await deleteS3ObjectSafely(oldS3Key);
                    }
                } catch(cleanupError) {
                    console.error("Failed to clean up old QR code from S3:", cleanupError);
                }
            }
        }

        await dynamoDB.update({
            TableName: TABLE_LEVELS,
            Key: { levelName },
            UpdateExpression: updateExpression,
            ExpressionAttributeValues: expressionAttributeValues
        }).promise();

        res.json({ message: 'Level updated successfully.' });
    } catch (error) { 
        console.error("Edit Level Error:", error);
        res.status(500).json({ error: 'Failed to update level' }); 
    }
});

/* ==========================================================================
   ADMIN CONTENT & S3 UPLOADS
   ========================================================================== */
app.post('/api/admin/content/upload-url', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { fileName, fileType } = req.body;
        const fileKey = `assets/${uuidv4()}-${fileName.replace(/[^a-zA-Z0-9.\-_]/g, '')}`;
        
        // Expiration is set to 3 hours (10800 seconds) 
        // This ensures 1.5GB videos don't time out mid-upload on slower internet connections.
        const params = { Bucket: S3_BUCKET, Key: fileKey, Expires: 10800, ContentType: fileType };
        
        const uploadUrl = await s3.getSignedUrlPromise('putObject', params);
        const readUrl = `https://${S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
        
        res.json({ uploadUrl, s3Key: fileKey, readUrl });
    } catch (error) { 
        console.error("S3 Upload URL Error:", error);
        res.status(500).json({ error: 'Upload URL generation failed. Check AWS configuration.' }); 
    }
});


app.post('/api/admin/content', authenticateToken, isAdmin, async (req, res) => {
    try {
        let { id, title, levels, type, textContent, s3Key, parentId, order, status } = req.body;
        const contentId = id || uuidv4();
        let finalS3Key = s3Key;
        
        // --- NEW SAFETY CHECK --- 
        // Forcefully strip parentId from Chapters to guarantee they stay at the root directory
        if (type === 'chapter') {
            parentId = null; 
        }
        
        if (id && !s3Key) {
             const existing = await dynamoDB.get({ TableName: TABLE_CONTENT, Key: { id } }).promise();
             if (existing.Item) finalS3Key = existing.Item.s3Key;
        }

        if (id && s3Key) {
            const existing = await dynamoDB.get({ TableName: TABLE_CONTENT, Key: { id } }).promise();
            if (existing.Item && existing.Item.s3Key && existing.Item.s3Key !== s3Key) {
                await deleteS3ObjectSafely(existing.Item.s3Key);
            }
        }

        const newContent = {
            id: contentId, title, levels: levels || [], type, textContent, s3Key: finalS3Key,
            parentId: parentId || null, order: order || 0, status: status || 'published',
            updatedAt: new Date().toISOString()
        };
        if(!id) newContent.createdAt = new Date().toISOString();
        
        await dynamoDB.put({ TableName: TABLE_CONTENT, Item: newContent }).promise();
        res.status(201).json({ message: 'Content saved', contentId });
    } catch (error) { res.status(500).json({ error: 'Failed to save content' }); }
});

app.get('/api/admin/content', authenticateToken, isAdmin, async (req, res) => {
    try {
        const data = await dynamoDB.scan({ TableName: TABLE_CONTENT }).promise();
        res.json(data.Items || []);
    } catch (error) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.delete('/api/admin/content/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const contentId = req.params.id;
        const existing = await dynamoDB.get({ TableName: TABLE_CONTENT, Key: { id: contentId } }).promise();
        
        if (existing.Item && existing.Item.s3Key) {
            await deleteS3ObjectSafely(existing.Item.s3Key); 
        }
        
        await dynamoDB.delete({ TableName: TABLE_CONTENT, Key: { id: contentId } }).promise();
        res.json({ message: 'Content deleted from database and storage.' });
    } catch (error) { res.status(500).json({ error: 'Delete failed' }); }
});

/* ==========================================================================
   ADMIN RECORDINGS (VIDEO CLASSES)
   ========================================================================== */
app.post('/api/admin/recordings', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id, title, type, parentId, levels, notes, s3Key, status } = req.body;
        const recordingId = id || uuidv4();
        let finalS3Key = s3Key;
        
        if (id && !s3Key && type === 'video') {
             const existing = await dynamoDB.get({ TableName: TABLE_RECORDINGS, Key: { id } }).promise();
             if (existing.Item) finalS3Key = existing.Item.s3Key;
        }

        if (id && s3Key && type === 'video') {
            const existing = await dynamoDB.get({ TableName: TABLE_RECORDINGS, Key: { id } }).promise();
            if (existing.Item && existing.Item.s3Key && existing.Item.s3Key !== s3Key) {
                await deleteS3ObjectSafely(existing.Item.s3Key);
            }
        }

        const newRecord = {
            id: recordingId, title, type, parentId: parentId || null, 
            levels: levels || [], notes: notes || '', s3Key: finalS3Key || null,
            status: status || 'published', updatedAt: new Date().toISOString()
        };
        if(!id) newRecord.createdAt = new Date().toISOString();
        
        await dynamoDB.put({ TableName: TABLE_RECORDINGS, Item: newRecord }).promise();
        res.status(201).json({ message: 'Recording saved', recordingId });
    } catch (error) { res.status(500).json({ error: 'Failed to save recording' }); }
});

app.get('/api/admin/recordings', authenticateToken, isAdmin, async (req, res) => {
    try {
        const data = await dynamoDB.scan({ TableName: TABLE_RECORDINGS }).promise();
        res.json(data.Items || []);
    } catch (error) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.delete('/api/admin/recordings/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const recordId = req.params.id;
        const existing = await dynamoDB.get({ TableName: TABLE_RECORDINGS, Key: { id: recordId } }).promise();
        
        if (existing.Item && existing.Item.s3Key) {
            await deleteS3ObjectSafely(existing.Item.s3Key);
        }
        
        await dynamoDB.delete({ TableName: TABLE_RECORDINGS, Key: { id: recordId } }).promise();
        res.json({ message: 'Recording deleted securely.' });
    } catch (error) { res.status(500).json({ error: 'Delete failed' }); }
});

/* ==========================================================================
   ADMIN ASSESSMENTS / TESTS
   ========================================================================== */
app.post('/api/admin/tests', authenticateToken, isAdmin, async (req, res) => {
    try {
        const testData = req.body;
        if (!testData.id) { testData.id = uuidv4(); testData.createdAt = new Date().toISOString(); }
        testData.updatedAt = new Date().toISOString();
        if (!Array.isArray(testData.levels)) { testData.levels = testData.levels ? [testData.levels] : []; }

        // BUG FIX: Bulletproof extraction of invalid/empty start dates for DynamoDB
        if (!testData.startTime || typeof testData.startTime !== 'string' || testData.startTime.trim() === "" || testData.startTime === "null") {
            delete testData.startTime;
        }

        // Remove endTime as it is now determined dynamically by student subscription expiry
        delete testData.endTime;

        await dynamoDB.put({ TableName: TABLE_TESTS, Item: testData }).promise();
        res.status(201).json({ message: 'Test saved', testId: testData.id });
    } catch (error) { res.status(500).json({ error: 'Failed to save test' }); }
});

app.get('/api/admin/tests', authenticateToken, isAdmin, async (req, res) => {
    try {
        const data = await dynamoDB.scan({ TableName: TABLE_TESTS }).promise();
        res.json(data.Items || []);
    } catch (error) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.delete('/api/admin/tests/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await dynamoDB.delete({ TableName: TABLE_TESTS, Key: { id: req.params.id } }).promise();
        res.json({ message: 'Test deleted' });
    } catch (error) { res.status(500).json({ error: 'Delete failed' }); }
});

app.get('/api/admin/reports', authenticateToken, isAdmin, async (req, res) => {
    try {
        const data = await dynamoDB.scan({ TableName: TABLE_SCORES }).promise();
        res.json(data.Items || []);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch reports' }); }
});

/* ==========================================================================
   STUDENT CONTENT CONSUMPTION (SECURE STREAMING & INHERITANCE)
   ========================================================================== */

// SUPER IMPORTANT: Robust Inheritance Engine for Folder Hierarchies
const getAccessibleTree = (allItems, userLevel) => {
    if (!allItems || !Array.isArray(allItems)) return [];
    
    const itemsById = new Map();
    allItems.forEach(item => itemsById.set(item.id, item));

    const isAccessible = (id, currentPath = new Set()) => {
        if (!id || currentPath.has(id)) return false; // Prevent infinite loops
        currentPath.add(id);
        
        const item = itemsById.get(id);
        if (!item) return false;

        const levels = item.levels || [];
        
        // 1. Explicitly granted access
        if (levels.includes(userLevel) || levels.includes('All Levels')) {
            return true;
        }
        
        // 2. Explicitly restricted (it HAS levels assigned, but user isn't in them)
        if (levels.length > 0) {
            return false;
        }
        
        // 3. Implicitly granted via inheritance (levels array is completely empty)
        // Check if the parent allows access
        if (item.parentId) {
            return isAccessible(item.parentId, new Set(currentPath));
        }

        return false;
    };

    const accessibleIds = new Set();

    // Evaluate every item
    allItems.forEach(item => {
        if (isAccessible(item.id)) {
            accessibleIds.add(item.id);
            // Force-add all ancestors to ensure the tree structure doesn't break in the UI
            let parentId = item.parentId;
            while (parentId && !accessibleIds.has(parentId)) {
                accessibleIds.add(parentId);
                const parent = itemsById.get(parentId);
                if (parent) parentId = parent.parentId;
                else break;
            }
        }
    });

    // FIX: Filter out any 'undefined' items caused by orphaned parentId references
    return Array.from(accessibleIds)
        .map(id => itemsById.get(id))
        .filter(item => item !== undefined && item !== null);
};

app.get('/api/student/content', authenticateToken, async (req, res) => {
    try {
        const { level } = req.user;
        const data = await dynamoDB.scan({
            TableName: TABLE_CONTENT,
            FilterExpression: '#st = :status',
            ExpressionAttributeNames: { '#st': 'status' },
            ExpressionAttributeValues: { ':status': 'published' }
        }).promise();
        
        // Apply Inheritance Engine
        const accessibleContent = getAccessibleTree(data.Items || [], level);

        const contentWithSecureUrls = await Promise.all(accessibleContent.map(async (item) => {
            // BUG FIX: Removed strict type checking. If it has an S3 Key, generate the URL!
            if (item && item.s3Key) {
                try {
                    const urlParams = { Bucket: S3_BUCKET, Key: item.s3Key, Expires: 3600 };
                    item.mediaUrl = await s3.getSignedUrlPromise('getObject', urlParams);
                } catch(awsErr) {
                    item.mediaUrl = null; 
                }
            }
            return item;
        }));
        res.json(contentWithSecureUrls);
    } catch (error) { 
        console.error("Student content fetch error:", error);
        res.status(500).json({ error: 'Content fetch failed' }); 
    }
});

app.get('/api/student/recordings', authenticateToken, async (req, res) => {
    try {
        const { level } = req.user;
        const data = await dynamoDB.scan({
            TableName: TABLE_RECORDINGS,
            FilterExpression: '#st = :status',
            ExpressionAttributeNames: { '#st': 'status' },
            ExpressionAttributeValues: { ':status': 'published' }
        }).promise();

        // Apply Inheritance Engine
        let accessible = getAccessibleTree(data.Items || [], level);

        // Sort chronologically so lessons appear in the order they were created by the admin
        accessible = accessible.sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0));

        const withUrls = await Promise.all(accessible.map(async (item) => {
            // Defensive check added here (item && item.s3Key)
            if (item && item.s3Key && item.type === 'video') {
                try {
                    const urlParams = { Bucket: S3_BUCKET, Key: item.s3Key, Expires: 3600 };
                    item.mediaUrl = await s3.getSignedUrlPromise('getObject', urlParams);
                } catch(awsErr) {
                    item.mediaUrl = null;
                }
            }
            return item;
        }));
        
        res.json(withUrls);
    } catch (error) { 
        res.status(500).json({ error: 'Recordings fetch failed' }); 
    }
});
/* ==========================================================================
   STUDENT ASSESSMENTS
   ========================================================================== */
app.get('/api/student/tests', authenticateToken, async (req, res) => {
    try {
        const { level, email } = req.user;
        const testData = await dynamoDB.scan({
            TableName: TABLE_TESTS,
            FilterExpression: '#st = :status',
            ExpressionAttributeNames: { '#st': 'status' },
            ExpressionAttributeValues: { ':status': 'published' }
        }).promise();
        
        const scoreData = await dynamoDB.scan({
            TableName: TABLE_SCORES,
            FilterExpression: 'studentEmail = :em',
            ExpressionAttributeValues: { ':em': email }
        }).promise();
        
        const studentScores = scoreData.Items || [];
        const now = new Date();
        
        // BUG FIX: Standardize casing to completely bypass mismatches
        const userLevel = (level || '').trim().toLowerCase(); 

        const accessibleTests = (testData.Items || []).filter(test => {
            const levels = (test.levels || []).map(l => l.trim().toLowerCase());
            const hasLevelAccess = levels.includes(userLevel) || levels.includes('all levels');
            
            // BUG FIX: Strict date evaluation, defaulting to true if no start date
            let hasCommenced = true;
            if (test.startTime && test.startTime !== null && test.startTime.trim() !== "") {
                const startDate = new Date(test.startTime);
                if (!isNaN(startDate.getTime())) {
                    hasCommenced = startDate <= now;
                }
            }
            
            return hasLevelAccess && hasCommenced;
        });

        const sanitizedTests = accessibleTests.map(test => {
            let maxAttempts = 1; 
            if (test.levelAttempts) {
                // Normalize keys inside levelAttempts for case-insensitive fetching
                const normAttempts = {};
                for (let k in test.levelAttempts) normAttempts[k.trim().toLowerCase()] = test.levelAttempts[k];

                if (normAttempts[userLevel] !== undefined && normAttempts[userLevel] !== null) {
                    maxAttempts = parseInt(normAttempts[userLevel], 10);
                } else if (normAttempts['all levels'] !== undefined && normAttempts['all levels'] !== null) {
                    maxAttempts = parseInt(normAttempts['all levels'], 10);
                }
            }
            
            const attemptCount = studentScores.filter(s => s.testId === test.id).length;
            const safeQuestions = (test.questions || []).map(q => {
                const { correctOptions, ...safeQ } = q; 
                return safeQ;
            });
            return { ...test, questions: safeQuestions, attemptCount, maxAttempts };
        });
        
        res.json(sanitizedTests);
    } catch (error) { 
        console.error("Test fetch error:", error);
        res.status(500).json({ error: 'Failed to fetch tests' }); 
    }
});

app.post('/api/student/tests/submit', authenticateToken, async (req, res) => {
    try {
        const { email, name, level } = req.user;
        const { testId, responses } = req.body;
        
        const testRes = await dynamoDB.get({ TableName: TABLE_TESTS, Key: { id: testId } }).promise();
        const test = testRes.Item;
        if (!test) return res.status(404).json({ error: 'Test not found' });

        const pastSubmissions = await dynamoDB.scan({
            TableName: TABLE_SCORES,
            FilterExpression: 'testId = :tid AND studentEmail = :em',
            ExpressionAttributeValues: { ':tid': testId, ':em': email }
        }).promise();
        
        const attemptCount = (pastSubmissions.Items || []).length;
        
        // BUG FIX: Use identical casing strategy when submitting the test
        const userLevel = (level || '').trim().toLowerCase();
        
        let maxAttempts = 1; 
        if (test.levelAttempts) {
             const normAttempts = {};
             for (let k in test.levelAttempts) normAttempts[k.trim().toLowerCase()] = test.levelAttempts[k];

             if (normAttempts[userLevel] !== undefined && normAttempts[userLevel] !== null) {
                 maxAttempts = parseInt(normAttempts[userLevel], 10);
             } else if (normAttempts['all levels'] !== undefined && normAttempts['all levels'] !== null) {
                 maxAttempts = parseInt(normAttempts['all levels'], 10);
             }
        }

        if (attemptCount >= maxAttempts) {
            return res.status(403).json({ error: `You have reached the maximum allowed attempts (${maxAttempts}).` });
        }

        let totalScore = 0; let maxScore = 0;

        (test.questions || []).forEach(q => {
            const posMarks = q.positiveMarks !== undefined ? parseFloat(q.positiveMarks) : 3;
            const negMarks = q.negativeMarks !== undefined ? parseFloat(q.negativeMarks) : 1;
            maxScore += posMarks;
            
            const studentAns = responses[q.id];
            if (studentAns === undefined || studentAns === null || studentAns === '' || (Array.isArray(studentAns) && studentAns.length === 0)) return;

            if (q.type === 'mcq') {
                if (Array.isArray(studentAns) && studentAns[0] === q.correctOptions[0]) totalScore += posMarks;
                else totalScore -= negMarks;
            } else if (q.type === 'msq') {
                if (Array.isArray(studentAns)) {
                    const sortedStudent = [...studentAns].sort();
                    const sortedCorrect = [...q.correctOptions].sort();
                    const isCorrect = sortedStudent.length === sortedCorrect.length && sortedStudent.every((val, index) => val === sortedCorrect[index]);
                    if (isCorrect) totalScore += posMarks; else totalScore -= negMarks;
                } else { totalScore -= negMarks; }
            } else if (q.type === 'fib') {
                if (typeof studentAns === 'string' && studentAns.trim().toLowerCase() === q.correctOptions[0].toLowerCase()) totalScore += posMarks;
                else totalScore -= negMarks;
            }
        });

        const scorePercentage = maxScore > 0 ? (totalScore / maxScore) * 100 : 0;
        const passingScore = parseFloat(test.passingScore) || 50;
        const passed = scorePercentage >= passingScore;

        const submission = {
            id: uuidv4(), testId, testTitle: test.title, studentEmail: email, studentName: name, level: userLevel,
            responses, totalScore, maxScore, scorePercentage: scorePercentage.toFixed(2), passed,
            attemptNumber: attemptCount + 1, submittedAt: new Date().toISOString()
        };

        await dynamoDB.put({ TableName: TABLE_SCORES, Item: submission }).promise();

        const responsePayload = {
            message: 'Test submitted successfully',
            result: { passed, scorePercentage: scorePercentage.toFixed(2), totalScore, maxScore, responses, attemptNumber: attemptCount + 1, maxAttempts },
            testSettings: { releaseResults: test.releaseResults, showAnswers: test.showAnswersImmediately }
        };

        if (test.showAnswersImmediately) responsePayload.questions = test.questions; 
        res.status(201).json(responsePayload);

    } catch (error) { 
        console.error("Submission error:", error);
        res.status(500).json({ error: 'Failed to process submission' }); 
    }
});


app.post('/api/admin/generate-questions-from-text', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) return res.status(400).json({ error: 'Text content from PDF is required.' });

        const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
        if (!OPENROUTER_API_KEY) {
            return res.status(500).json({ error: 'OpenRouter API key is not configured in the environment.' });
        }

        // Expanded string limit to capture massive documents
        const safeText = text.substring(0, 80000); 

        const prompt = `
        You are an expert AI examination parser.
        Analyze the following text extracted from a document. The text likely contains a massive list of existing test questions, options, and an answer key at the bottom.

        YOUR MISSION:
        1. Extract EVERY SINGLE question found in the text. If there are 110 questions, you MUST extract all 110. Do not stop early.
        2. Accurately map the correct answer for each question using the answer key provided in the text.
        3. If the text is just plain study material (no existing questions found), GENERATE 20 high-quality questions covering the core concepts.

        Classify each question into one of exactly three types:
        - 'mcq' (Single correct option)
        - 'msq' (Multiple correct options)
        - 'fib' (Fill in the blanks / Short exact answer)

        IMPORTANT: Your output MUST strictly follow the JSON schema provided.
        Each object MUST have the following keys:
        - "text" (string): The question text.
        - "type" (string): 'mcq', 'msq', or 'fib'.
        - "options" (array of strings): Options for mcq/msq. Empty [] for fib.
        - "correctOptions" (array of strings): 0-based indices as strings (e.g. ["0", "2"]). For fib, the exact answer string.

        Text to analyze:
        """
        ${safeText}
        """
        `;

        const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "openai/gpt-4o-mini", 
                messages: [{ role: "user", content: prompt }],
                response_format: {
                    type: "json_schema",
                    json_schema: {
                        name: "exam_parser",
                        strict: true,
                        schema: {
                            type: "object",
                            properties: {
                                questions: {
                                    type: "array",
                                    items: {
                                        type: "object",
                                        properties: {
                                            text: { type: "string" },
                                            type: { type: "string", enum: ["mcq", "msq", "fib"] },
                                            options: { type: "array", items: { type: "string" } },
                                            correctOptions: { type: "array", items: { type: "string" } }
                                        },
                                        required: ["text", "type", "options", "correctOptions"],
                                        additionalProperties: false
                                    }
                                }
                            },
                            required: ["questions"],
                            additionalProperties: false
                        }
                    }
                },
                max_tokens: 16000, 
                temperature: 0.1 
            })
        });

        if (!response.ok) {
            console.error("OpenRouter API Error:", await response.text());
            return res.status(500).json({ error: 'Failed to communicate with the AI model.' });
        }

        const data = await response.json();
        
        if (data.choices[0].finish_reason === 'length') {
            console.warn("AI response hit max_tokens length limit. Output may be truncated.");
        }

        let aiText = data.choices[0].message.content.trim();
        
        // Scrub markdown code block tags if the AI ignores instructions
        if (aiText.startsWith('```json')) aiText = aiText.slice(7);
        if (aiText.startsWith('```')) aiText = aiText.slice(3);
        if (aiText.endsWith('```')) aiText = aiText.slice(0, -3);

        const parsed = JSON.parse(aiText.trim());
        
        // Ensure the response matches our expected structure even if schema partially failed
        const questions = Array.isArray(parsed.questions) ? parsed.questions : (Array.isArray(parsed) ? parsed : []);

        res.json({ questions });

    } catch (error) {
        console.error("AI Question Generation Error:", error);
        res.status(500).json({ error: 'Failed to parse AI output. The document may be too large or the format too complex.' });
    }
});

app.get('/api/student/tests/history', authenticateToken, async (req, res) => {
    try {
        const { email } = req.user;
        const scoreData = await dynamoDB.scan({
            TableName: TABLE_SCORES,
            FilterExpression: 'studentEmail = :em',
            ExpressionAttributeValues: { ':em': email }
        }).promise();
        
        // Sort history descending by submission date
        const history = (scoreData.Items || []).sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
        res.json(history);
    } catch (error) {
        console.error("Test history fetch error:", error);
        res.status(500).json({ error: 'Failed to fetch test history' }); 
    }
});


/* ==========================================================================
   GLOBAL ERROR HANDLER
   ========================================================================== */
app.use(express.static('public'));

// Boot Server
app.listen(PORT, () => console.log(`🚀 Geeky Researcher Enterprise Backend running securely on port ${PORT}`));
