// Readers and writers for the handful of S3 XML documents the console speaks.
// Readers walk direct children only (a ListBucketResult has a <Prefix> of its
// own and one inside every <CommonPrefixes>) and refuse a document that is not
// the one asked for, so an <Error> sent with a 200 never reads as an empty
// result.

import { JayError } from './api.js';

function kids(el, name) {
  return Array.from(el.children).filter((c) => c.localName === name);
}

function textOf(el, name) {
  const first = kids(el, name)[0];
  return first ? first.textContent : '';
}

// expectRoot returns the document element after checking its name. A 200 whose
// body is an S3 <Error> becomes the error it says it is.
function expectRoot(doc, name) {
  const root = doc?.documentElement;
  if (!root) throw new JayError({ source: 's3', message: `jay answered without an XML document where ${name} was expected.` });
  if (root.localName === 'Error') {
    throw new JayError({
      source: 's3',
      code: textOf(root, 'Code'),
      message: textOf(root, 'Message') || 'jay answered with an error document.',
      s3RequestId: textOf(root, 'RequestId'),
    });
  }
  if (root.localName !== name) {
    throw new JayError({ source: 's3', message: `jay answered with <${root.localName}> where <${name}> was expected.` });
  }
  return root;
}

export function parseListObjects(doc) {
  const root = expectRoot(doc, 'ListBucketResult');
  return {
    prefixes: kids(root, 'CommonPrefixes').map((cp) => textOf(cp, 'Prefix')),
    objects: kids(root, 'Contents').map((c) => ({
      key: textOf(c, 'Key'),
      size: Number(textOf(c, 'Size')),
      lastModified: textOf(c, 'LastModified'),
      etag: textOf(c, 'ETag'),
    })),
    truncated: textOf(root, 'IsTruncated') === 'true',
    nextToken: textOf(root, 'NextContinuationToken'),
  };
}

export function parseDeleteResult(doc) {
  const root = expectRoot(doc, 'DeleteResult');
  return {
    deleted: kids(root, 'Deleted').map((d) => textOf(d, 'Key')),
    errors: kids(root, 'Error').map((e) => ({ key: textOf(e, 'Key'), code: textOf(e, 'Code'), message: textOf(e, 'Message') })),
  };
}

export function parseUploads(doc) {
  const root = expectRoot(doc, 'ListMultipartUploadsResult');
  return {
    uploads: kids(root, 'Upload').map((u) => ({ key: textOf(u, 'Key'), uploadId: textOf(u, 'UploadId'), initiated: textOf(u, 'Initiated') })),
    truncated: textOf(root, 'IsTruncated') === 'true',
  };
}

export function parseInitiate(doc) {
  const root = expectRoot(doc, 'InitiateMultipartUploadResult');
  const id = textOf(root, 'UploadId');
  if (!id) throw new JayError({ source: 's3', message: 'jay started a multipart upload but sent no upload id.' });
  return id;
}

// parseComplete reads the ETag of a finished multipart upload. CompleteMultipartUpload
// can fail after it has already answered 200, with the failure in the body.
export function parseComplete(doc) {
  const root = expectRoot(doc, 'CompleteMultipartUploadResult');
  return textOf(root, 'ETag');
}

// checkCopyResult refuses a 200 copy response that is really an <Error>.
export function checkCopyResult(doc) {
  expectRoot(doc, 'CopyObjectResult');
}

export function xmlEscape(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function buildDeleteBody(keys) {
  return `<Delete><Quiet>false</Quiet>${keys.map((k) => `<Object><Key>${xmlEscape(k)}</Key></Object>`).join('')}</Delete>`;
}

// buildCompleteBody takes [{ number, etag }] and sorts it by part number.
export function buildCompleteBody(parts) {
  const sorted = parts.slice().sort((a, b) => a.number - b.number);
  return `<CompleteMultipartUpload>${sorted.map((p) => `<Part><PartNumber>${p.number}</PartNumber><ETag>${xmlEscape(p.etag)}</ETag></Part>`).join('')}</CompleteMultipartUpload>`;
}
