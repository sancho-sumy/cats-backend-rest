import mongoose, { Document } from 'mongoose';
import bcrypt from 'bcrypt';
import config from 'config';

export interface UserInput {
    email: string;
    name: string;
    password: string;
    picture: string;
}

export interface UserDocument extends UserInput, Document {
    createdAt: Date;
    updatedAt: Date;
    comparePassword(providedPassword: string): Promise<boolean>;
}

const userSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: true,
            unique: true,
        },
        name: {
            type: String,
            required: true,
        },
        password: {
            type: String,
            select: false,
            required: true,
        },
        picture: {
            type: String,
        },
    },
    { timestamps: true },
);

userSchema.pre('save', async function (next) {
    let user = this as UserDocument;

    if (!user.isModified('password')) {
        return next();
    }

    const salt = await bcrypt.genSalt(config.get<number>('security.saltWorkFactor'));
    const hash = await bcrypt.hash(user.password, salt);

    user.password = hash;
    return next();
});

userSchema.methods.comparePassword = async function (providedPassword: string): Promise<boolean> {
    let user = this as UserDocument;

    return bcrypt.compare(providedPassword, user.password).catch(err => false);
};

const UserModel = mongoose.model<UserDocument>('User', userSchema);

export default UserModel;
