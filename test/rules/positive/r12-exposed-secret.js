// expect: exposed-secret
// An AWS access key ID in front-end code (AWS's own documented example key, not a real one).
var s3 = new AWS.S3({ accessKeyId: 'AKIAIOSFODNN7EXAMPLE', region: 'us-east-1' });
