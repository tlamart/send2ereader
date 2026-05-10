# node 20 is lts at the time of writing
FROM node:lts-alpine AS dependencies

# Create app directory
WORKDIR /usr/src/app

# Copy files needed by npm install
COPY package*.json ./

# Install app dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

FROM node:lts-alpine

# Create app directory
WORKDIR /usr/src/app

# Download and install kepubify and kindlegen
RUN wget -q -O /usr/local/bin/kepubify https://github.com/pgaskin/kepubify/releases/download/v4.0.4/kepubify-linux-64bit && \
    echo "37d7628d26c5c906f607f24b36f781f306075e7073a6fe7820a751bb60431fc5  /usr/local/bin/kepubify" | sha256sum -c && \
    chmod +x /usr/local/bin/kepubify && \
    wget -q https://github.com/zzet/fp-docker/raw/f2b41fb0af6bb903afd0e429d5487acc62cb9df8/kindlegen_linux_2.6_i386_v2_9.tar.gz && \
    echo "9828db5a2c8970d487ada2caa91a3b6403210d5d183a7e3849b1b206ff042296 kindlegen_linux_2.6_i386_v2_9.tar.gz" | sha256sum -c && \
    mkdir kindlegen && \
    tar xzf kindlegen_linux_2.6_i386_v2_9.tar.gz --directory kindlegen && \
    cp kindlegen/kindlegen /usr/local/bin/kindlegen && \
    chmod +x /usr/local/bin/kindlegen && \
    rm -rf kindlegen kindlegen_linux_2.6_i386_v2_9.tar.gz

# Copy runtime app files
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
COPY package*.json ./
COPY index.js ./
COPY static ./static

# Create uploads directory if it doesn't exist
RUN mkdir uploads && \
    chown -R node:node /usr/src/app

USER node

EXPOSE 3001
CMD [ "npm", "start" ]
