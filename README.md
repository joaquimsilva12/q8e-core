# q8e source
q8ecoin Q8E development tree

q8ecoin is a PoW PoS-based cryptocurrency.

Development process
Developers work in their own trees, then submit pull requests when they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a good thing. Developers should expect to rework and resubmit patches if they don't match the project's coding conventions (see coding.txt) or are controversial.

The master branch is regularly built and tested, but is not guaranteed to be completely stable. Tags are regularly created to indicate new stable release versions of q8ecoin.

Feature branches are created when there are major new features being worked on by several people.

From time to time a pull request will become outdated. If this occurs, and the pull is no longer automatically mergeable; a comment on the pull will be used to issue a warning of closure. The pull will be closed 15 days after the warning if action is not taken by the author. Pull requests closed in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after 15 days from their last activity. Issues closed in this manner will be labeled 'stale'.


q8e-qt: Qt5 GUI for Cheese
===============================

Build instructions
===================

Debian
-------

First, make sure that the required packages for Qt5 development of your
distribution are installed, for Debian and Ubuntu these are:

::

    apt-get install qt5-default qt5-qmake qtbase5-dev-tools qttools5-dev-tools \
        build-essential libboost-dev libboost-system-dev \
        libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev \
        libssl-dev libdb++-dev libminiupnpc-dev

then execute the following:

::

    qmake
    make

Alternatively, install Qt Creator and open the `q8e-qt.pro` file.

An executable named `q8e-qt` will be built.
