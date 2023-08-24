FROM adoptopenjdk:17-jdk-hotspot

FROM maven:3.8.7

RUN mkdir -p /home/app

WORKDIR /home/app

COPY . /home/app

RUN mvn clean

CMD mvn spring-boot:run