// S3 interface
package s3

// FIXME need to prevent anything but ListDir working for s3://

/*
Issues found

FIXME Report:
Substitution method prone to repeat substitutions
- use method submitted to googleapi

FIXME - nil checks

FIXME - region / endpoint stuff
*/

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/swift"
	"github.com/stripe/aws-go/aws"
	"github.com/stripe/aws-go/gen/s3"
)

// Register with Fs
func init() {
	fs.Register(&fs.FsInfo{
		Name:  "s3",
		NewFs: NewFs,
		// AWS endpoints: http://docs.amazonwebservices.com/general/latest/gr/rande.html#s3_region
		Options: []fs.Option{{
			Name: "access_key_id",
			Help: "AWS Access Key ID.",
		}, {
			Name: "secret_access_key",
			Help: "AWS Secret Access Key (password). ",
		}, {
			Name: "endpoint",
			Help: "Endpoint for S3 API.",
			Examples: []fs.OptionExample{{
				Value: "https://s3.amazonaws.com/",
				Help:  "The default endpoint - a good choice if you are unsure.\nUS Region, Northern Virginia or Pacific Northwest.\nLeave location constraint empty.",
			}, {
				Value: "https://s3-external-1.amazonaws.com",
				Help:  "US Region, Northern Virginia only.\nLeave location constraint empty.",
			}, {
				Value: "https://s3-us-west-2.amazonaws.com",
				Help:  "US West (Oregon) Region\nNeeds location constraint us-west-2.",
			}, {
				Value: "https://s3-us-west-1.amazonaws.com",
				Help:  "US West (Northern California) Region\nNeeds location constraint us-west-1.",
			}, {
				Value: "https://s3-eu-west-1.amazonaws.com",
				Help:  "EU (Ireland) Region Region\nNeeds location constraint EU or eu-west-1.",
			}, {
				Value: "https://s3-ap-southeast-1.amazonaws.com",
				Help:  "Asia Pacific (Singapore) Region\nNeeds location constraint ap-southeast-1.",
			}, {
				Value: "https://s3-ap-southeast-2.amazonaws.com",
				Help:  "Asia Pacific (Sydney) Region\nNeeds location constraint .",
			}, {
				Value: "https://s3-ap-northeast-1.amazonaws.com",
				Help:  "Asia Pacific (Tokyo) Region\nNeeds location constraint ap-northeast-1.",
			}, {
				Value: "https://s3-sa-east-1.amazonaws.com",
				Help:  "South America (Sao Paulo) Region\nNeeds location constraint sa-east-1.",
			}},
		}, {
			Name: "location_constraint",
			Help: "Location constraint - must be set to match the Endpoint.",
			Examples: []fs.OptionExample{{
				Value: "",
				Help:  "Empty for US Region, Northern Virginia or Pacific Northwest.",
			}, {
				Value: "us-west-2",
				Help:  "US West (Oregon) Region.",
			}, {
				Value: "us-west-1",
				Help:  "US West (Northern California) Region.",
			}, {
				Value: "eu-west-1",
				Help:  "EU (Ireland) Region.",
			}, {
				Value: "EU",
				Help:  "EU Region.",
			}, {
				Value: "ap-southeast-1",
				Help:  "Asia Pacific (Singapore) Region.",
			}, {
				Value: "ap-southeast-2",
				Help:  "Asia Pacific (Sydney) Region.",
			}, {
				Value: "ap-northeast-1",
				Help:  "Asia Pacific (Tokyo) Region.",
			}, {
				Value: "sa-east-1",
				Help:  "South America (Sao Paulo) Region.",
			}},
		}},
	})
}

// Constants
const (
	metaMtime = "X-Amz-Meta-Mtime" // the meta key to store mtime in
)

// FsS3 represents a remote s3 server
type FsS3 struct {
	c                  *s3.S3          // the connection to the s3 server
	bucket             string          // the bucket we are working on
	perm               aws.StringValue // permissions for new buckets / objects
	root               string          // root of the bucket - ignore all objects above this
	locationConstraint string          // location constraint of new buckets
}

// FsObjectS3 describes a s3 object
type FsObjectS3 struct {
	// Will definitely have everything but meta which may be nil
	//
	// List will read everything but meta - to fill that in need to call
	// readMetaData
	s3           *FsS3             // what this object is part of
	remote       string            // The remote path
	etag         string            // md5sum of the object
	bytes        int64             // size of the object
	lastModified time.Time         // Last modified
	meta         map[string]string // The object metadata if known - may be nil
}

// ------------------------------------------------------------

// String converts this FsS3 to a string
func (f *FsS3) String() string {
	if f.root == "" {
		return fmt.Sprintf("S3 bucket %s", f.bucket)
	}
	return fmt.Sprintf("S3 bucket %s path %s", f.bucket, f.root)
}

// Pattern to match a s3 path
var matcher = regexp.MustCompile(`^([^/]*)(.*)$`)

// parseParse parses a s3 'url'
func s3ParsePath(path string) (bucket, directory string, err error) {
	parts := matcher.FindStringSubmatch(path)
	if parts == nil {
		err = fmt.Errorf("Couldn't parse bucket out of s3 path %q", path)
	} else {
		bucket, directory = parts[1], parts[2]
		directory = strings.Trim(directory, "/")
	}
	return
}

// s3Connection makes a connection to s3
func s3Connection(name string) (*s3.S3, error) {
	// Make the auth
	accessKeyId := fs.ConfigFile.MustValue(name, "access_key_id")
	if accessKeyId == "" {
		return nil, errors.New("access_key_id not found")
	}
	secretAccessKey := fs.ConfigFile.MustValue(name, "secret_access_key")
	if secretAccessKey == "" {
		return nil, errors.New("secret_access_key not found")
	}
	auth := aws.Creds(accessKeyId, secretAccessKey, "")

	// FIXME look through all the regions by name and use one of them if found

	// Synthesize the region
	s3Endpoint := fs.ConfigFile.MustValue(name, "endpoint")
	if s3Endpoint == "" {
		s3Endpoint = "https://s3.amazonaws.com/"
	}
	// FIXME
	// region := aws.Region{
	// 	Name:                 "s3",
	// 	S3Endpoint:           s3Endpoint,
	// 	S3LocationConstraint: false,
	// }
	// s3LocationConstraint := fs.ConfigFile.MustValue(name, "location_constraint")
	// if s3LocationConstraint != "" {
	// 	region.Name = s3LocationConstraint
	// 	region.S3LocationConstraint = true
	// }
	region := fs.ConfigFile.MustValue(name, "location_constraint")

	c := s3.New(auth, region, nil)
	return c, nil
}

// NewFsS3 contstructs an FsS3 from the path, bucket:path
func NewFs(name, root string) (fs.Fs, error) {
	bucket, directory, err := s3ParsePath(root)
	if err != nil {
		return nil, err
	}
	c, err := s3Connection(name)
	if err != nil {
		return nil, err
	}
	f := &FsS3{
		c:      c,
		bucket: bucket,
		// FIXME perm:   s3.Private, // FIXME need user to specify
		root:               directory,
		locationConstraint: fs.ConfigFile.MustValue(name, "location_constraint"),
	}
	if f.root != "" {
		f.root += "/"
		// Check to see if the object exists
		req := s3.HeadObjectRequest{
			Bucket: &f.bucket,
			Key:    &directory,
		}
		_, err = f.c.HeadObject(&req)
		if err == nil {
			remote := path.Base(directory)
			f.root = path.Dir(directory)
			if f.root == "." {
				f.root = ""
			} else {
				f.root += "/"
			}
			obj := f.NewFsObject(remote)
			// return a Fs Limited to this object
			return fs.NewLimited(f, obj), nil
		}
	}
	return f, nil
}

// Return an FsObject from a path
//
// May return nil if an error occurred
func (f *FsS3) newFsObjectWithInfo(remote string, info *s3.Object) fs.Object {
	o := &FsObjectS3{
		s3:     f,
		remote: remote,
	}
	if info != nil {
		// Set info but not meta
		if info.LastModified.IsZero() {
			fs.Log(o, "Failed to read last modified")
			o.lastModified = time.Now()
		} else {
			o.lastModified = info.LastModified
		}
		o.etag = *info.ETag  // FIXME nil
		o.bytes = *info.Size // FIXME nil
	} else {
		err := o.readMetaData() // reads info and meta, returning an error
		if err != nil {
			// logged already FsDebug("Failed to read info: %s", err)
			return nil
		}
	}
	return o
}

// Return an FsObject from a path
//
// May return nil if an error occurred
func (f *FsS3) NewFsObject(remote string) fs.Object {
	return f.newFsObjectWithInfo(remote, nil)
}

// list the objects into the function supplied
//
// If directories is set it only sends directories
func (f *FsS3) list(directories bool, fn func(string, *s3.Object)) {
	delimiter := ""
	if directories {
		delimiter = "/"
	}
	maxKeys := 10000
	// FIXME need to implement ALL loop
	req := s3.ListObjectsRequest{
		Bucket:    &f.bucket,
		Delimiter: &delimiter,
		Prefix:    &f.root,
		MaxKeys:   &maxKeys,
	}
	resp, err := f.c.ListObjects(&req)
	if err != nil {
		fs.Stats.Error()
		fs.Log(f, "Couldn't read bucket %q: %s", f.bucket, err)
	} else {
		rootLength := len(f.root)
		if directories {
			for _, commonPrefix := range resp.CommonPrefixes {
				if commonPrefix.Prefix == nil {
					fs.Log(f, "Nil common prefix received")
					continue
				}
				remote := *commonPrefix.Prefix
				if !strings.HasPrefix(remote, f.root) {
					fs.Log(f, "Odd name received %q", remote)
					continue
				}
				remote = remote[rootLength:]
				if strings.HasSuffix(remote, "/") {
					remote = remote[:len(remote)-1]
				}
				fn(remote, &s3.Object{Key: &remote})
			}
		} else {
			for i := range resp.Contents {
				object := &resp.Contents[i]
				key := *object.Key // FIXME nil *object.Key?
				if !strings.HasPrefix(key, f.root) {
					fs.Log(f, "Odd name received %q", key)
					continue
				}
				remote := key[rootLength:]
				fn(remote, object)
			}
		}
	}
}

// Walk the path returning a channel of FsObjects
func (f *FsS3) List() fs.ObjectsChan {
	out := make(fs.ObjectsChan, fs.Config.Checkers)
	if f.bucket == "" {
		// Return no objects at top level list
		close(out)
		fs.Stats.Error()
		fs.Log(f, "Can't list objects at root - choose a bucket using lsd")
	} else {
		go func() {
			defer close(out)
			f.list(false, func(remote string, object *s3.Object) {
				if fs := f.newFsObjectWithInfo(remote, object); fs != nil {
					out <- fs
				}
			})
		}()
	}
	return out
}

// Lists the buckets
func (f *FsS3) ListDir() fs.DirChan {
	out := make(fs.DirChan, fs.Config.Checkers)
	if f.bucket == "" {
		// List the buckets
		go func() {
			defer close(out)
			resp, err := f.c.ListBuckets()
			if err != nil {
				fs.Stats.Error()
				fs.Log(f, "Couldn't list buckets: %s", err)
			} else {
				for _, bucket := range resp.Buckets {
					out <- &fs.Dir{
						Name:  *bucket.Name, // FIXME nil
						When:  bucket.CreationDate,
						Bytes: -1,
						Count: -1,
					}
				}
			}
		}()
	} else {
		// List the directories in the path in the bucket
		go func() {
			defer close(out)
			f.list(true, func(remote string, object *s3.Object) {
				size := int64(0)
				if object.Size != nil {
					size = *object.Size
				}
				out <- &fs.Dir{
					Name:  remote,
					Bytes: size,
					Count: 0,
				}
			})
		}()
	}
	return out
}

// Put the FsObject into the bucket
func (f *FsS3) Put(in io.Reader, remote string, modTime time.Time, size int64) (fs.Object, error) {
	// Temporary FsObject under construction
	fs := &FsObjectS3{s3: f, remote: remote}
	return fs, fs.Update(in, modTime, size)
}

// Mkdir creates the bucket if it doesn't exist
func (f *FsS3) Mkdir() error {
	req := s3.CreateBucketRequest{
		Bucket: &f.bucket,
		ACL:    f.perm,
	}
	if f.locationConstraint != "" {
		req.CreateBucketConfiguration = &s3.CreateBucketConfiguration{
			LocationConstraint: &f.locationConstraint,
		}
	}
	_, err := f.c.CreateBucket(&req)
	if err, ok := err.(*aws.APIError); ok {
		if err.Code == "BucketAlreadyOwnedByYou" {
			return nil
		}
	}
	return err
}

// Rmdir deletes the bucket
//
// Returns an error if it isn't empty
func (f *FsS3) Rmdir() error {
	req := s3.DeleteBucketRequest{
		Bucket: &f.bucket,
	}
	return f.c.DeleteBucket(&req)
}

// Return the precision
func (f *FsS3) Precision() time.Duration {
	return time.Nanosecond
}

// ------------------------------------------------------------

// Return the parent Fs
func (o *FsObjectS3) Fs() fs.Fs {
	return o.s3
}

// Return a string version
func (o *FsObjectS3) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Return the remote path
func (o *FsObjectS3) Remote() string {
	return o.remote
}

// Md5sum returns the Md5sum of an object returning a lowercase hex string
func (o *FsObjectS3) Md5sum() (string, error) {
	return strings.Trim(strings.ToLower(o.etag), `"`), nil
}

// Size returns the size of an object in bytes
func (o *FsObjectS3) Size() int64 {
	return o.bytes
}

// readMetaData gets the metadata if it hasn't already been fetched
//
// if we get a 404 error then we retry a few times for eventual
// consistency reasons
//
// it also sets the info
func (o *FsObjectS3) readMetaData() (err error) {
	if o.meta != nil {
		return nil
	}
	key := o.s3.root + o.remote
	req := s3.HeadObjectRequest{
		Bucket: &o.s3.bucket,
		Key:    &key,
	}
	var resp *s3.HeadObjectOutput

	// Try reading the metadata a few times (with exponential
	// backoff) to get around eventual consistency on 404 error
	for tries := uint(0); tries < 10; tries++ {
		resp, err = o.s3.c.HeadObject(&req)
		if err == nil {
			break
		}
		if awsErr, ok := err.(aws.APIError); ok {
			if awsErr.StatusCode == http.StatusNotFound {
				time.Sleep(5 * time.Millisecond << tries)
				continue
			}
		}
		break
	}
	if err != nil {
		fs.Debug(o, "Failed to read info: %s", err)
		return err
	}
	var size int64
	// Ignore missing Content-Length assuming it is 0
	// Some versions of ceph do this due their apache proxies
	if resp.ContentLength != nil {
		size = *resp.ContentLength
	}
	o.etag = *resp.ETag // FIXME nil
	o.bytes = size
	o.meta = resp.Metadata
	if o.lastModified, err = time.Parse(http.TimeFormat, o.meta["Last-Modified"]); err != nil {
		fs.Log(o, "Failed to read last modified from HEAD: %s", err)
		o.lastModified = time.Now()
	}
	return nil
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *FsObjectS3) ModTime() time.Time {
	err := o.readMetaData()
	if err != nil {
		fs.Log(o, "Failed to read metadata: %s", err)
		return time.Now()
	}
	// read mtime out of metadata if available
	d, ok := o.meta[metaMtime]
	if !ok {
		// fs.Debug(o, "No metadata")
		return o.lastModified
	}
	modTime, err := swift.FloatStringToTime(d)
	if err != nil {
		fs.Log(o, "Failed to read mtime from object: %s", err)
		return o.lastModified
	}
	return modTime
}

// Sets the modification time of the local fs object
func (o *FsObjectS3) SetModTime(modTime time.Time) {
	err := o.readMetaData()
	if err != nil {
		fs.Stats.Error()
		fs.Log(o, "Failed to read metadata: %s", err)
		return
	}
	o.meta[metaMtime] = swift.TimeToFloatString(modTime)

	// Copy the object to itself to update the metadata
	key := o.s3.root + o.remote
	sourceKey := o.s3.bucket + "/" + key
	directive := s3.MetadataDirectiveReplace // replace metadata with that passed in
	req := s3.CopyObjectRequest{
		Bucket:            &o.s3.bucket,
		ACL:               o.s3.perm,
		Key:               &key,
		CopySource:        &sourceKey,
		Metadata:          o.meta,
		MetadataDirective: &directive,
	}
	_, err = o.s3.c.CopyObject(&req)
	if err != nil {
		fs.Stats.Error()
		fs.Log(o, "Failed to update remote mtime: %s", err)
	}
}

// Is this object storable
func (o *FsObjectS3) Storable() bool {
	return true
}

// Open an object for read
func (o *FsObjectS3) Open() (in io.ReadCloser, err error) {
	key := o.s3.root + o.remote
	req := s3.GetObjectRequest{
		Bucket: &o.s3.bucket,
		Key:    &key,
	}
	resp, err := o.s3.c.GetObject(&req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Wrap an io.Reader to make it an io.ReadCloser
type readCloser struct {
	io.Reader
}

// Pretend to close the io.Reader
func (r *readCloser) Close() error {
	return nil
}

// Check it implements the interface
var _ io.ReadCloser = (*readCloser)(nil)

// Update the Object from in with modTime and size
func (o *FsObjectS3) Update(in io.Reader, modTime time.Time, size int64) error {
	// Set the mtime in the meta data
	metadata := map[string]string{
		metaMtime: swift.TimeToFloatString(modTime),
	}

	// Guess the content type
	contentType := mime.TypeByExtension(path.Ext(o.remote))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	key := o.s3.root + o.remote
	req := s3.PutObjectRequest{
		Bucket:        &o.s3.bucket,
		ACL:           o.s3.perm,
		Key:           &key,
		Body:          &readCloser{in},
		ContentLength: &size,
		ContentType:   &contentType,
		Metadata:      metadata,
	}
	_, err := o.s3.c.PutObject(&req)
	if err != nil {
		return err
	}
	// Read the metadata from the newly created object
	o.meta = nil // wipe old metadata
	err = o.readMetaData()
	return err
}

// Remove an object
func (o *FsObjectS3) Remove() error {
	key := o.s3.root + o.remote
	req := s3.DeleteObjectRequest{
		Bucket: &o.s3.bucket,
		Key:    &key,
	}
	_, err := o.s3.c.DeleteObject(&req)
	return err
}

// Check the interfaces are satisfied
var _ fs.Fs = &FsS3{}
var _ fs.Object = &FsObjectS3{}
