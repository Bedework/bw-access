## bw-util [![Build Status](https://travis-ci.org/Bedework/bw-access.svg)](https://travis-ci.org/Bedework/bw-access)

This project provides a number of access control classes and methods for
[Bedework](https://www.apereo.org/projects/bedework).

These classes implement access control as described in the WebDAV and
 CalDAV standards.

### Requirements

1. JDK 11
2. Maven 3

### Building Locally

> mvn clean install

### Releasing

Releases of this fork are published to Maven Central via Sonatype.

To create a release, you must have:

1. Permissions to publish to the `org.bedework` groupId.
2. `gpg` installed with a published key (release artifacts are signed).

To perform a new release:

> mvn -P bedework-dev release:clean release:prepare

When prompted, select the desired version; accept the defaults for scm tag and next development version.
When the build completes, and the changes are committed and pushed successfully, execute:

> mvn -P bedework-dev release:perform

For full details, see [Sonatype's documentation for using Maven to publish releases](http://central.sonatype.org/pages/apache-maven.html).

## Release Notes
### 4.0.3
* Update library versions

#### 4.0.4
* Update library versions
* Use bw-util-logging.

#### 4.0.5
* Update library versions

#### 4.0.6
* Update library versions

#### 4.0.7
* Update library versions

#### 4.0.8
* Update library versions

#### 4.0.9
* Update library versions

#### 4.0.10
* Update library versions

#### 5.0.0
* Use bedework-parent for builds
*  Upgrade library versions

#### 5.0.1
*  Upgrade library versions

