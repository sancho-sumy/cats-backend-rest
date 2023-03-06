import * as dotenv from 'dotenv';

dotenv.config();

const SERVER_PORT = process.env.SERVER_PORT || 7070;

const origin = 'http://localhost:3000';

const MONGO_DB_URI = process.env.MONGO_DB_URI;

const PUBLIC_KEY = process.env.PUBLIC_KEY;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

const saltWorkFactor = 10;
const accessTokenTtl = '15m';
const refreshTokenTtl = '1y';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const googleOauthRedirectURL = 'http://localhost:7070/api/sessions/oauth/google';

export default {
    server: {
        port: SERVER_PORT,
        origin: origin,
    },
    db: {
        uri: MONGO_DB_URI,
    },
    security: {
        publicKey: PUBLIC_KEY,
        privateKey: PRIVATE_KEY,
        saltWorkFactor: saltWorkFactor,
        accessTokenTtl: accessTokenTtl,
        refreshTokenTtl: refreshTokenTtl,
    },
    google: {
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        googleOauthRedirectURL: googleOauthRedirectURL,
    },
};
