# ==============================================================================
# ShieldDesk IAM Service — Multi-Stage Distroless Dockerfile
# ==============================================================================

# Stage 1: Build & Compile TypeScript
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json ./
RUN npm install --ignore-scripts

COPY tsconfig.json ./
COPY src ./src
RUN npx tsc

# Stage 2: Production Distroless Runtime
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4000

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

EXPOSE 4000
USER nonroot

CMD ["dist/index.js"]
