-- Professional.description: use TEXT so entries up to the API limit (1000 chars) persist.
-- Prisma's default String maps to VARCHAR(191) on MySQL, which caused "Data too long" errors.

ALTER TABLE `Professional` MODIFY `description` TEXT NULL;
