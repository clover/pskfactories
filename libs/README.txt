These libraries have been built with debugging symbols included to allow for interactive debugging.

Instructions based on v1.78. Recommend sdkman for installing multiple java versions.

git clone https://github.com/bcgit/bc-java

export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
export BC_JDK21=/path/to/java21

Use java 17 and gradle 8.1.1

    gradle --no-daemon jar
    gradle --no-daemon sourcesJar
    gradle --no-daemon javadocJar
