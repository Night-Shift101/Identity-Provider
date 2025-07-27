/*
  Warnings:

  - You are about to drop the column `deviceId` on the `trusted_devices` table. All the data in the column will be lost.
  - You are about to drop the column `fingerprint` on the `trusted_devices` table. All the data in the column will be lost.
  - You are about to drop the column `ipAddress` on the `trusted_devices` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `trusted_devices` table. All the data in the column will be lost.
  - You are about to drop the column `userAgent` on the `trusted_devices` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[userId,deviceHash]` on the table `trusted_devices` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `deviceHash` to the `trusted_devices` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `trusted_devices` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "trusted_devices_userId_deviceId_key";

-- AlterTable
ALTER TABLE "trusted_devices" DROP COLUMN "deviceId",
DROP COLUMN "fingerprint",
DROP COLUMN "ipAddress",
DROP COLUMN "name",
DROP COLUMN "userAgent",
ADD COLUMN     "deviceHash" TEXT NOT NULL,
ADD COLUMN     "deviceName" TEXT,
ADD COLUMN     "firstIP" TEXT,
ADD COLUMN     "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "lastIP" TEXT,
ADD COLUMN     "metadata" JSONB,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL;

-- CreateIndex
CREATE INDEX "trusted_devices_userId_idx" ON "trusted_devices"("userId");

-- CreateIndex
CREATE INDEX "trusted_devices_deviceHash_idx" ON "trusted_devices"("deviceHash");

-- CreateIndex
CREATE UNIQUE INDEX "trusted_devices_userId_deviceHash_key" ON "trusted_devices"("userId", "deviceHash");
