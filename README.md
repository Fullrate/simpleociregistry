Simple OCI Registry
===================

This is a very simple OCI registry for use with Kubernetes/rkt or anything else
that pulls gzipped tarball OCI images from a Docker v2 HTTP API endpoint.

Unlike most other registries, this one loads OCI images directly from disk. This
makes it ideal for development, as well as for use in (especially) on-premises
clusters where NFS or similar is used as a shared storage medium.

The registry is designed to be deployed on every node in a Kubernetes cluster,
and be reachable via a /etc/hosts entry pointing to the local node. This can be
accomplished e.g. with a DaemonSet.

Getting started
---------------

Deploy the registry application in any way you see fit, and supply it with the
--dir option to indicate the root of the images folder.

Image names and references are mapped to .oci files. The candidates for a given
<name>:<reference> are, in order, relative to the image dir:

  - `<name>/<reference>.oci`
  - `<name>/*.oci`
  - `<name>:<reference>.oci`
  - `<name>:*.oci`
  - `<name>.oci`

The available images are found by expanding the above globs, and then searching
through the matching files until a matching reference is found. In general
a single <name>:<reference> pair should be found in only a single file to avoid
problems, but this is not enforced by the registry itself.

Internals
---------

Internally the daemon simply scans OCI tarballs and serve the contained blobs
directly to requesting clients.

When a manifest is requested for an image <name>:<reference>, the paths
discussed in [Getting Started](#getting-started) are scanned until an image
containing the reference is found. This(and only this) reference, along with all
blobs in the image are then cached. Blobs are only cached if they are not
already present in the cache.

The next time the same image is referenced, the list of paths will be checked
for files newer than the current one, and if such a file is found the cache will
be updated. If no newer files are found, the cache will be served directly.

If an image <name>:<reference> is deleted, the cache will be automatically
rescanned on the next request, and if no replacement image is created the entry
will be purged entirely. The cache is also rescanned every 10 minutes.

Disclaimer
----------

This registry is in use at Fullrate. This registry is _not_ designed to be
a super-scalable general-purpose solution.
