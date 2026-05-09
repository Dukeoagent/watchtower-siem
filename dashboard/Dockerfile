FROM node:20-alpine as builder

WORKDIR /app
COPY package.json .
RUN npm install

COPY . .
RUN npm run build

# Serve the built files with nginx
FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
