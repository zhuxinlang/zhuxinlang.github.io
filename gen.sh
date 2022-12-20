#!/bin/bash
find ../ -name ".DS_Store" -depth -exec rm {} \;
#dpkg-scanpackages -m ./debs > ./Packages
#bzip2 -fks ./Packages

dpkg-scanpackages -m ./debs /dev/null > ./Packages
tar zcvf ./Packages.gz ./Packages
bzip2 -fks ./Packages
