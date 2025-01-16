Release process
---------------

1. Update the version of the Maven artifacts:

       mvn versions:set -DnewVersion=x.y -DgenerateBackupPoms=false

   The version in the documentation and in the Gradle examples will be automatically updated by `mvn deploy`.

1. Update the release date in `README.md`

1. Upload the Maven artifacts to Nexus:

       mvn clean deploy -Prelease

1. Login to https://oss.sonatype.org and release the Nexus staging repository

1. Review and commit the changes

1. Tag the release:

       git tag x.y

1. Create a release on GitHub, and upload the all-in-one jar and the DEB and RPM packages

1. Close the current milestone on GitHub and create a new one

1. Publish the release on Chocolatey (see `jsign/src/choco/README.md`)

1. Login to https://manage.fury.io/login and publish the Debian package

1. Publish the Gradle plugin (see `jsign-gradle-plugin/README.md`)

1. Update the Maven version to the next snapshot:

       mvn versions:set -DnewVersion=x.y+1-SNAPSHOT -DgenerateBackupPoms=false -DupdateBuildOutputTimestamp=false

1. Commit and push the changes

1. Announce the release and celebrate!
