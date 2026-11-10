const { createWriteStream } = require('node:fs');
const { pipeline } = require('node:stream/promises');
const { S3Client, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');

const s3 = new S3Client({
    region: 'us-east-1',
    credentials: {
        accessKeyId: 'YOUR-ACCESSKEYID',
        secretAccessKey: 'YOUR-SECRETACCESSKEY',
    },
    endpoint: 'http://127.0.0.1:9000',
    forcePathStyle: true,
});

// Add the extension header before the SDK signs each request.
s3.middlewareStack.add((next) => async (args) => {
    args.request.headers['X-Minio-Extract'] = 'true';
    return next(args);
}, { step: 'build', name: 'minioExtract' });

async function main() {
    // List all contents stored in the zip archive.
    const listing = await s3.send(new ListObjectsV2Command({
        Bucket: 'your-bucket', Prefix: 'path/to/file.zip/',
    }));
    console.log('Success', listing);

    // Download a file in the archive and store it in /tmp/data.csv.
    const object = await s3.send(new GetObjectCommand({
        Bucket: 'your-bucket', Key: 'path/to/file.zip/data.csv',
    }));
    await pipeline(object.Body, createWriteStream('/tmp/data.csv'));
}

main().catch((err) => {
    console.error('Error', err);
    process.exitCode = 1;
});
