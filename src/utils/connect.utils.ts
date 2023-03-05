import mongoose from 'mongoose';
import logger from './logger.utils';
import config from 'config';


async function connect() {
    const dbUri = config.get<string>('db.uri');

    try {
        await mongoose.connect(dbUri);
        logger.info('Connected to DB');
    } catch (error) {
        logger.error('Could not connect to DB');
        process.exit(1);
    }
}

export default connect;
