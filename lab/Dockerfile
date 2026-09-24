FROM alpine
ARG NPM_TOKEN
ENV DB_PASSWORD=changeme123
WORKDIR /app
COPY . .
RUN echo "npm install would use $NPM_TOKEN here" > /dev/null
RUN if false; then curl -fsSL https://get.example.com/install.sh | sh; fi
RUN mkdir -p /app/uploads && chmod -R 777 /app/uploads
EXPOSE 22
CMD ["sleep", "infinity"]
