import config from 'config';
import axios from 'axios';
import qs from 'qs';
import { omit } from 'lodash';
import { FilterQuery, QueryOptions, UpdateQuery } from 'mongoose';
import UserModel, { UserDocument, UserInput } from '../models/user.model';
import logger from '../utils/logger.utils';

interface GoogleTokensResult {
    access_token: string;
    expires_in: number;
    refresh_token: string;
    scope: string;
    id_token: string;
}

interface GoogleUserResult {
    id: string;
    email: string;
    verified_email: boolean;
    name: string;
    given_name: string;
    family_name: string;
    picture: string;
    locale: string;
}

export async function createUser(input: UserInput) {
    try {
        const user = await UserModel.create(input);
        console.log(user);

        return omit(user.toJSON(), 'password');
    } catch (error: any) {
        throw new Error(error);
    }
}

export async function validatePassword({ email, password }: { email: string; password: string }) {
    const user = await UserModel.findOne({ email }).exec();

    if (!user) {
        return false;
        //! Add error handling
    }

    const isValid = await user.comparePassword(password);

    if (!isValid) {
        return false;
        //! Add error handling
    }

    return omit(user.toJSON(), 'password');
}

export async function findUser(query: FilterQuery<UserDocument>) {
    return UserModel.findOne(query).lean();
}

export async function getGoogleOauthTokens({ code }: { code: string }): Promise<GoogleTokensResult> {
    const url = 'https://oauth2.googleapis.com/token';
    const values = {
        code,
        client_id: config.get('google.clientId'),
        client_secret: config.get('google.clientSecret'),
        redirect_uri: config.get('google.googleOauthRedirectURL'),
        grant_type: 'authorization_code',
    };

    try {
        const res = await axios.post<GoogleTokensResult>(url, qs.stringify(values), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        return res.data;
    } catch (error: any) {
        console.error(error.response.data.error);
        logger.error(error, 'Failed to fetch Google Oauth Tokens');
        throw new Error(error.message);
    }
}

export async function getGoogleUser({
    id_token,
    access_token,
}: {
    id_token: string;
    access_token: string;
}): Promise<GoogleUserResult> {
    try {
        const res = await axios.get(
            `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
            {
                headers: {
                    Authorization: `Bearer ${id_token}`,
                },
            },
        );
        console.log(res.data);

        return res.data;
    } catch (error: any) {
        logger.error(error, 'Failed to fetch Google user information');
        throw new Error(error.message);
    }
}

export async function findAndUpdateUser(
    query: FilterQuery<UserDocument>,
    update: UpdateQuery<UserDocument>,
    options: QueryOptions = {},
) {
    return UserModel.findOneAndUpdate(query, update, options);
}
