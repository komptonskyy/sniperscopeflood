const express = require("express");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;

if (!BOT_TOKEN) {
    console.error("❌ В .env отсутствует TELEGRAM_BOT_TOKEN");
    process.exit(1);
}

if (!JWT_SECRET) {
    console.error("❌ В .env отсутствует JWT_SECRET");
    process.exit(1);
}

app.use(express.json());
app.use(cookieParser());

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


/* =====================================
   ПРОВЕРКА TELEGRAM
===================================== */

function verifyTelegram(data) {

    const { hash, ...telegramData } = data;

    if (!hash) {
        return false;
    }

    const checkString =
        Object.keys(telegramData)
            .filter(key =>
                telegramData[key] !== undefined &&
                telegramData[key] !== null
            )
            .sort()
            .map(key =>
                `${key}=${telegramData[key]}`
            )
            .join("\n");


    const secretKey =
        crypto
            .createHash("sha256")
            .update(BOT_TOKEN)
            .digest();


    const calculatedHash =
        crypto
            .createHmac(
                "sha256",
                secretKey
            )
            .update(checkString)
            .digest("hex");


    try {

        return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(calculatedHash, "hex")
        );

    } catch {

        return false;

    }
}


/* =====================================
   TELEGRAM LOGIN
===================================== */

app.post(
    "/api/auth/telegram",
    (req, res) => {

        try {

            const telegramUser = req.body;

            if (!verifyTelegram(telegramUser)) {

                return res.status(401).json({
                    success: false,
                    error: "Telegram-подпись не прошла проверку"
                });

            }


            /* Проверяем свежесть входа */

            const now =
                Math.floor(Date.now() / 1000);

            const authDate =
                Number(telegramUser.auth_date);


            if (
                !authDate ||
                now - authDate > 600
            ) {

                return res.status(401).json({
                    success: false,
                    error: "Авторизация Telegram устарела"
                });

            }


            /* Ищем пользователя */

            let user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE telegram_id = ?
                `)
                .get(
                    String(telegramUser.id)
                );


            /* Регистрация */

            if (!user) {

                const result =
                    db.prepare(`
                        INSERT INTO users (
                            telegram_id,
                            username,
                            first_name,
                            last_name,
                            photo_url
                        )
                        VALUES (?, ?, ?, ?, ?)
                    `)
                    .run(
                        String(telegramUser.id),
                        telegramUser.username || null,
                        telegramUser.first_name || null,
                        telegramUser.last_name || null,
                        telegramUser.photo_url || null
                    );


                user =
                    db.prepare(`
                        SELECT *
                        FROM users
                        WHERE id = ?
                    `)
                    .get(result.lastInsertRowid);


                console.log(
                    `✅ Новый пользователь: ${user.username || user.telegram_id}`
                );

            }

            /* Повторный вход */

            else {

                db.prepare(`
                    UPDATE users
                    SET
                        username = ?,
                        first_name = ?,
                        last_name = ?,
                        photo_url = ?,
                        last_login_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `)
                .run(
                    telegramUser.username || null,
                    telegramUser.first_name || null,
                    telegramUser.last_name || null,
                    telegramUser.photo_url || null,
                    user.id
                );


                user =
                    db.prepare(`
                        SELECT *
                        FROM users
                        WHERE id = ?
                    `)
                    .get(user.id);

            }


            /* Бан */

            if (user.banned) {

                return res.status(403).json({
                    success: false,
                    error: "Ваш аккаунт заблокирован."
                });

            }


            /* Создаём сессию */

            const token =
                jwt.sign(
                    {
                        userId: user.id,
                        telegramId: user.telegram_id
                    },
                    JWT_SECRET,
                    {
                        expiresIn: "30d"
                    }
                );


            res.cookie(
                "brawl_session",
                token,
                {
                    httpOnly: true,
                    sameSite: "lax",

                    secure:
                        process.env.NODE_ENV === "production",

                    maxAge:
                        30 * 24 * 60 * 60 * 1000
                }
            );


            return res.json({
                success: true,

                user: {
                    id: user.id,
                    telegram_id: user.telegram_id,
                    username: user.username,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    photo_url: user.photo_url,
                    role: user.role,
                    warnings: user.warnings
                }
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                error: "Ошибка сервера"
            });

        }

    }
);


/* =====================================
   ПРОВЕРКА СЕССИИ
===================================== */

function requireAuth(req, res, next) {

    const token =
        req.cookies.brawl_session;


    if (!token) {

        return res.status(401).json({
            success: false,
            error: "Не авторизован"
        });

    }


    try {

        req.session =
            jwt.verify(
                token,
                JWT_SECRET
            );

        next();

    } catch {

        return res.status(401).json({
            success: false,
            error: "Сессия закончилась"
        });

    }

}


/* =====================================
   МОЙ ПРОФИЛЬ
===================================== */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const user =
            db.prepare(`
                SELECT
                    id,
                    telegram_id,
                    username,
                    first_name,
                    last_name,
                    photo_url,
                    role,
                    warnings,
                    banned,
                    created_at

                FROM users

                WHERE id = ?
            `)
            .get(req.session.userId);


        if (!user) {

            return res.status(404).json({
                success: false
            });

        }


        if (user.banned) {

            return res.status(403).json({
                success: false,
                error: "Аккаунт заблокирован"
            });

        }


        res.json({
            success: true,
            user
        });

    }
);


/* =====================================
   ВЫХОД
===================================== */

app.post(
    "/api/logout",
    (req, res) => {

        res.clearCookie(
            "brawl_session"
        );

        res.json({
            success: true
        });

    }
);


/* =====================================
   START
===================================== */

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(`✅ Server started on port ${PORT}`);
    }
);
    
