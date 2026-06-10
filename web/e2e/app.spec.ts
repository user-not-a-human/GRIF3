import { expect, test, type Page } from "@playwright/test";

async function openDemoImage(page: Page) {
  await page.request.post("http://127.0.0.1:8765/api/demo");
}

test("открывает демонстрационный образ и проверяет суперблок ext4", async ({ page }) => {
  await openDemoImage(page);
  await page.goto("/");

  await expect(page.getByText("ГРИФ").first()).toBeVisible();

  await expect(page.getByLabel("Сводка источника").getByText("ext4", { exact: true })).toBeVisible();
  await expect(page.getByText("demo_ext4")).toBeVisible();

  await page.getByRole("button", { name: "ФС" }).click();
  const activeFile = page.getByRole("button", { name: /active_demo\.txt/ });
  await expect(activeFile).toBeVisible();
  await activeFile.click();
  await expect(page.getByText("Инод #12")).toBeVisible();
  await expect(page.getByLabel("Смещение")).not.toHaveValue("0");

  await page.getByRole("button", { name: "Редактор" }).click();
  await page.getByLabel("Смещение").fill("0");
  await page.getByRole("button", { name: "Перейти к смещению" }).click();
  await page.getByTitle("0x00000000 = 00").click();
  await page.getByLabel("Значение байта").fill("AA");
  await page.getByRole("button", { name: "Записать" }).click();
  await expect(page.getByLabel("Журнал изменений").getByText(/Замена 1 байт/)).toBeVisible();
  await page.getByTitle("Отменить").click();

  await page.getByRole("button", { name: /Суперблок/ }).click();
  await expect(page.getByText("Суперблок ext4")).toBeVisible();
  await expect(page.getByText("s_magic")).toBeVisible();
  await expect(page.getByText("0xEF53")).toBeVisible();

  await page.getByRole("textbox", { name: "Блок" }).fill("1");
  await page.getByRole("button", { name: "Перейти к блоку" }).click();
  await expect(page.getByText("0x00000400").first()).toBeVisible();

  await page.getByLabel("Inode").fill("2");
  await page.getByRole("button", { name: "Перейти к иноду" }).click();
  await expect(page.getByText(/Инод|Ошибка/).first()).toBeVisible();

  await page.getByTitle("Корневой каталог").click();
  await expect(page.getByText(/Инод|Ошибка/).first()).toBeVisible();

  await page.getByLabel("Смещение").fill("0");
  await page.getByRole("button", { name: "Перейти к смещению" }).click();
  await page.getByPlaceholder("Введите текст").fill("demo_ext4");
  await page.getByRole("button", { name: "Найти" }).click();
  await expect(page.getByLabel("Смещение")).not.toHaveValue("0");
});

test("ищет следы, открывает карточку и скачивает файлы", async ({ page }) => {
  await openDemoImage(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Анализ" }).click();

  await page.getByRole("button", { name: "Найти" }).click();
  const recoverableRow = page.locator(".deleted-table", { hasText: "#13" }).first();
  await expect(recoverableRow).toBeVisible();
  await recoverableRow.click();

  await expect(page.getByText("HC_SECRET_DELETED_DEMO_2026_ALPHA")).toBeVisible();
  await expect(page.getByText("Карточка объединяет свойства inode")).toBeVisible();

  const recoveredDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать файл" }).click();
  await expect((await recoveredDownload).suggestedFilename()).toBe("recovered_inode_13.bin");

  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Отчёт inode" }).click();
  await expect((await reportDownload).suggestedFilename()).toBe("forensics_inode_13.md");

  await page.getByPlaceholder("Введите запрос для поиска").fill("secret");
  await page.getByRole("button", { name: "Найти" }).click();
  await expect(page.getByText("secret_folder/secret.txt").first()).toBeVisible();
  await page.locator(".artifact-row", { hasText: "secret_folder/secret.txt" }).first().click();
  await expect(page.getByText("Найденные имена").first()).toBeVisible();

  await page.getByRole("button", { name: "Хронология" }).first().click();
  await expect(page.getByText(/События|Хронология/).first()).toBeVisible();
});

test("показывает страницу снятия образа", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Образ" }).click();
  await expect(page.getByText("Снять образ устройства")).toBeVisible();
  await expect(page.getByText("Исходное устройство", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Новый образ")).toBeVisible();
});
