-- Idlescape: Discord-only accounts and short-lived web/game sessions.

-- AlterTable
ALTER TABLE "account" ADD COLUMN "discord_id" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "account_discord_id_key" ON "account"("discord_id");

-- CreateTable
CREATE TABLE "account_session" (
    "web_token" TEXT NOT NULL PRIMARY KEY,
    "game_token" TEXT,
    "account_id" INTEGER NOT NULL,
    "expires_at" DATETIME NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "account_session_game_token_key" ON "account_session"("game_token");

-- CreateIndex
CREATE INDEX "account_session_account_id_idx" ON "account_session"("account_id");
