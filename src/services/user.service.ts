import { omit } from 'lodash';
import { FilterQuery } from 'mongoose';
import UserModel, { UserDocument, UserInput } from '../models/user.model';

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
