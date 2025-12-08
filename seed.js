const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Seeding database...");

  // Create admin user
  const hashedPassword = await bcrypt.hash("admin123", 10);

  const admin = await prisma.user.upsert({
    where: { email: "admin@ismaal.com" },
    update: {},
    create: {
      email: "admin@ismaal.com",
      password: hashedPassword,
      name: "Admin User",
      role: "ADMIN",
    },
  });

  console.log("✅ Admin user created:", admin.email);

  // Create a sample regular user
  const userPassword = await bcrypt.hash("user123", 10);

  const user = await prisma.user.upsert({
    where: { email: "user@example.com" },
    update: {},
    create: {
      email: "user@example.com",
      password: userPassword,
      name: "Test User",
      role: "USER",
    },
  });

  console.log("✅ Test user created:", user.email);

  console.log("🎉 Database seeded successfully!");
}

main()
  .catch((e) => {
    console.error("❌ Error seeding database:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
