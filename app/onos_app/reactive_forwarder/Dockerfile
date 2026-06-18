FROM maven:3.8.6-eclipse-temurin-11 AS builder

WORKDIR /usr/src/app
# Copiar primero el pom para cachear dependencias
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copiar el código y compilar
COPY src ./src
RUN mvn clean package

# Mantener el contenedor vivo para extraer el archivo si es necesario o simplemente sacarlo con docker cp
CMD ["echo", "Compilación completada. El archivo OAR está en /usr/src/app/target/"]
