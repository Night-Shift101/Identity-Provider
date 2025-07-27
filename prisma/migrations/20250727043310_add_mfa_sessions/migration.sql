-- CreateTable
CREATE TABLE "mfa_sessions" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userAgent" TEXT,
    "ipAddress" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "isUsed" BOOLEAN NOT NULL DEFAULT false,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "maxAttempts" INTEGER NOT NULL DEFAULT 5,
    "lastAttemptAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mfa_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mfa_sessions_token_key" ON "mfa_sessions"("token");

-- CreateIndex
CREATE INDEX "mfa_sessions_token_idx" ON "mfa_sessions"("token");

-- CreateIndex
CREATE INDEX "mfa_sessions_userId_idx" ON "mfa_sessions"("userId");

-- CreateIndex
CREATE INDEX "mfa_sessions_expiresAt_idx" ON "mfa_sessions"("expiresAt");

-- AddForeignKey
ALTER TABLE "mfa_sessions" ADD CONSTRAINT "mfa_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
