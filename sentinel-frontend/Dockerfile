# Stage 1: Build the Next.js application
FROM node:20-alpine AS build-stage
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Serve the application
FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=build-stage /app/.next ./.next
COPY --from=build-stage /app/node_modules ./node_modules
COPY --from=build-stage /app/package.json ./package.json
COPY --from=build-stage /app/public ./public

EXPOSE 3000
CMD ["npm", "start"]