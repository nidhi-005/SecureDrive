const { S3Client, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const BUCKET = process.env.AWS_BUCKET_NAME;

async function uploadToS3(buffer, key) {
  const upload = new Upload({
    client: s3,
    params: {
      Bucket:      BUCKET,
      Key:         key,
      Body:        buffer,
      ContentType: 'application/octet-stream'
    }
  });
  await upload.done();
  return key;
}

async function downloadFromS3(key) {
  const command  = new GetObjectCommand({ Bucket: BUCKET, Key: key });
  const response = await s3.send(command);
  return response.Body;
}

async function deleteFromS3(key) {
  const command = new DeleteObjectCommand({ Bucket: BUCKET, Key: key });
  await s3.send(command);
}

module.exports = { uploadToS3, downloadFromS3, deleteFromS3 };