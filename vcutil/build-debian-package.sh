#!/bin/bash
## Usage:
##  ./vcutil/build-debian-package.sh

set -e
set -x

BUILD_PATH="/tmp/vcbuild"
PACKAGE_NAME="V-Dimension"
SRC_PATH=`pwd`
SRC_DEB=$SRC_PATH/contrib/debian
SRC_DOC=$SRC_PATH/doc

umask 022

if [ ! -d $BUILD_PATH ]; then
    mkdir $BUILD_PATH
fi

PACKAGE_VERSION=$($SRC_PATH/src/vdsd --version | grep version | cut -d' ' -f4 | tr -d v)
DEBVERSION=$(echo $PACKAGE_VERSION | sed 's/-beta/~beta/' | sed 's/-rc/~rc/' | sed 's/-/+/')
BUILD_DIR="$BUILD_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-amd64"

if [ -d $BUILD_DIR ]; then
    rm -R $BUILD_DIR
fi

DEB_BIN=$BUILD_DIR/usr/bin
DEB_CMP=$BUILD_DIR/usr/share/bash-completion/completions
DEB_DOC=$BUILD_DIR/usr/share/doc/$PACKAGE_NAME
DEB_MAN=$BUILD_DIR/usr/share/man/man1
mkdir -p $BUILD_DIR/DEBIAN $DEB_CMP $DEB_BIN $DEB_DOC $DEB_MAN
chmod 0755 -R $BUILD_DIR/*

# Package maintainer scripts (currently empty)
#cp $SRC_DEB/postinst $BUILD_DIR/DEBIAN
#cp $SRC_DEB/postrm $BUILD_DIR/DEBIAN
#cp $SRC_DEB/preinst $BUILD_DIR/DEBIAN
#cp $SRC_DEB/prerm $BUILD_DIR/DEBIAN
# Copy binaries
cp $SRC_PATH/src/vdsd $DEB_BIN
cp $SRC_PATH/src/vds-cli $DEB_BIN
cp $SRC_PATH/vcutil/fetch-params.sh $DEB_BIN/vds-fetch-params
# Strip binaries
strip $DEB_BIN/vdsd
strip $DEB_BIN/vds-cli
# Copy docs
#cp $SRC_PATH/doc/release-notes/release-notes-1.0.0.md $DEB_DOC/changelog
#cp $SRC_DEB/changelog $DEB_DOC/changelog.Debian
#cp $SRC_DEB/copyright $DEB_DOC
cp -r $SRC_DEB/examples $DEB_DOC
# Copy manpages
#cp $SRC_DOC/man/vdsd.1 $DEB_MAN
#cp $SRC_DOC/man/vds-cli.1 $DEB_MAN
#cp $SRC_DOC/man/vds-fetch-params.1 $DEB_MAN
# Copy bash completion files
#cp $SRC_PATH/contrib/bitcoind.bash-completion $DEB_CMP/vdsd
#cp $SRC_PATH/contrib/bitcoin-cli.bash-completion $DEB_CMP/vds-cli
# Gzip files
#gzip --best -n $DEB_DOC/changelog
#gzip --best -n $DEB_DOC/changelog.Debian
#gzip --best -n $DEB_MAN/vdsd.1
#gzip --best -n $DEB_MAN/vds-cli.1
#gzip --best -n $DEB_MAN/vds-fetch-params.1

cd $SRC_PATH/contrib

# Create the control file
dpkg-shlibdeps $DEB_BIN/vdsd $DEB_BIN/vds-cli
dpkg-gencontrol -P$BUILD_DIR -v$DEBVERSION

# Create the Debian package
fakeroot dpkg-deb --build $BUILD_DIR
cp $BUILD_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-amd64.deb $SRC_PATH
# Analyze with Lintian, reporting bugs and policy violations
# lintian -i -u $SRC_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-amd64.deb
exit 0
