const {
  S3Client,
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand
} = require('@aws-sdk/client-s3');
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

async function deleteAllUserFilesFromS3(userId) {
  if (!BUCKET) {
    throw new Error('AWS_BUCKET_NAME is not configured');
  }

  if (!/^[a-f\d]{24}$/i.test(String(userId))) {
    throw new Error('Invalid user ID');
  }

  const prefix = `${userId}/`;
  let continuationToken;

  do {
    const response = await s3.send(
      new ListObjectsV2Command({
        Bucket: BUCKET,
        Prefix: prefix,
        ContinuationToken: continuationToken
      })
    );

    const objects = (response.Contents || [])
      .filter(object => object.Key)
      .map(object => ({ Key: object.Key }));

    if (objects.length > 0) {
      const result = await s3.send(
        new DeleteObjectsCommand({
          Bucket: BUCKET,
          Delete: {
            Objects: objects,
            Quiet: false
          }
        })
      );

      // S3 can return HTTP success while individual deletions fail.
      if (result.Errors && result.Errors.length > 0) {
        throw new Error(
          `Failed to delete ${result.Errors.length} S3 object(s)`
        );
      }
    }

    continuationToken = response.IsTruncated
      ? response.NextContinuationToken
      : undefined;
  } while (continuationToken);
}

module.exports = {
  uploadToS3,
  downloadFromS3,
  deleteFromS3,
  deleteAllUserFilesFromS3
};