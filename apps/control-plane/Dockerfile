FROM node:24-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/control-plane/package.json apps/control-plane/package.json
RUN pnpm install --filter @operant/control-plane --frozen-lockfile

FROM deps AS build
COPY apps/control-plane apps/control-plane
RUN pnpm --filter @operant/control-plane build

FROM node:24-alpine AS prod-deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/control-plane/package.json apps/control-plane/package.json
RUN pnpm install --filter @operant/control-plane --prod --frozen-lockfile

FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV HOME=/home/node
ARG OPENCLAW_VERSION=2026.5.18
RUN corepack enable
RUN apk add --no-cache libstdc++ \
  && apk add --no-cache --virtual .openclaw-build-deps python3 make g++ \
  && npm install -g openclaw@${OPENCLAW_VERSION} \
  && apk del .openclaw-build-deps
RUN mkdir -p /operant/openclaw /home/node/.openclaw /home/node/.openclaw-client/agents/main/sessions /home/node/.openclaw-gateway-state \
  && chown -R node:node /app /operant /home/node/.openclaw /home/node/.openclaw-client /home/node/.openclaw-gateway-state \
  && chmod 700 /home/node/.openclaw /home/node/.openclaw-client /home/node/.openclaw-gateway-state
COPY --from=prod-deps --chown=node:node /app/node_modules /app/node_modules
COPY --from=prod-deps --chown=node:node /app/apps/control-plane/node_modules /app/apps/control-plane/node_modules
COPY --from=build --chown=node:node /app/apps/control-plane/package.json /app/apps/control-plane/package.json
COPY --from=build --chown=node:node /app/apps/control-plane/dist /app/apps/control-plane/dist
COPY --from=build --chown=node:node /app/apps/control-plane/public /app/apps/control-plane/public
COPY --from=build --chown=node:node /app/apps/control-plane/migrations /app/apps/control-plane/migrations
USER node
WORKDIR /app/apps/control-plane
EXPOSE 8080
CMD ["node", "dist/src/server.js"]
