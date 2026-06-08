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
      phone: "252700000001",
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
      phone: "252700000002",
      role: "USER",
    },
  });

  console.log("✅ Test user created:", user.email);

  const {
    defaultCities,
    businessCategories,
    productCategories,
    professionCategories,
  } = require("./lookupSeedData");

  if ((await prisma.lookupCity.count()) === 0) {
    await prisma.lookupCity.createMany({
      data: defaultCities.map((name, i) => ({
        name,
        sortOrder: i,
        active: true,
      })),
    });
    console.log(`✅ Seeded ${defaultCities.length} lookup cities`);
  } else {
    console.log("⏭️  Lookup cities already present, skipping");
  }

  async function seedCategoryType(type, names) {
    if ((await prisma.lookupCategory.count({ where: { type } })) > 0) {
      console.log(`⏭️  ${type} categories already present, skipping`);
      return;
    }
    await prisma.lookupCategory.createMany({
      data: names.map((name, i) => ({
        name,
        type,
        sortOrder: i,
        active: true,
      })),
    });
    console.log(`✅ Seeded ${names.length} ${type} categories`);
  }

  await seedCategoryType("business", businessCategories);
  await seedCategoryType("product", productCategories);
  await seedCategoryType("profession", professionCategories);

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
