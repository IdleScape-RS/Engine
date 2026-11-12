import crypto from 'crypto';

import * as bcrypt from 'bcrypt-ts';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { db, toDbDate } from '#/db/query.js';
import Environment from '#/util/Environment.js';
import { printInfo } from '#/util/Logger.js';
import { toSafeName } from '#/util/JString.js';

/**
 * Idlescape has no username/password login. A player authenticates with Discord in the browser,
 * and the resulting session cookie mints a single-use token that the web client sends as its
 * login password. The token is the only thing that ever crosses into the game protocol.
 */

const DISCORD_API = 'https://discord.com/api/v10';

const STATE_COOKIE = 'idlescape_oauth_state';
const SESSION_COOKIE = 'idlescape_session';

const STATE_TTL_SECONDS = 60 * 10;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;

type DiscordUser = {
    id: string;
    username: string;
    global_name: string | null;
};

/**
 * 15 bytes as base64url, i.e. exactly 20 characters. The game token is sent to the world as the
 * login packet's password, and that field is capped at 20 characters (World.ts), so a longer token
 * is silently reported to the player as "Invalid username or password". 120 bits is ample for a
 * single-use token with a 30 day expiry.
 */
function randomToken(): string {
    return crypto.randomBytes(15).toString('base64url');
}

function cookie(req: FastifyRequest, name: string): string | null {
    for (const part of (req.headers.cookie ?? '').split(';')) {
        const index = part.indexOf('=');
        if (index === -1) {
            continue;
        }

        if (part.slice(0, index).trim() === name) {
            return decodeURIComponent(part.slice(index + 1).trim());
        }
    }

    return null;
}

function setCookie(reply: FastifyReply, name: string, value: string, maxAgeSeconds: number) {
    const secure = Environment.discord.redirectUrl.startsWith('https:') ? '; Secure' : '';
    reply.header('set-cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`);
}

function loginErrorMessage(error: string): string {
    return `<html><body style="background:#000;color:#fff;font:14px sans-serif;padding:2rem">
        <h2>Could not sign in</h2><p>${error}</p><p>Close this tab and try again.</p></body></html>`;
}

async function discordUsersMe(accessToken: string): Promise<DiscordUser> {
    const res = await fetch(`${DISCORD_API}/users/@me`, {
        headers: { authorization: `Bearer ${accessToken}` }
    });

    if (!res.ok) {
        throw new Error(`Discord /users/@me returned ${res.status}`);
    }

    return (await res.json()) as DiscordUser;
}

async function uniqueUsername(wanted: string, discordId: string): Promise<string> {
    const base = toSafeName(wanted) || toSafeName(discordId);

    for (let suffix = 1; suffix < 100; suffix++) {
        const candidate = suffix === 1 ? base : `${base.slice(0, 12 - String(suffix).length)}${suffix}`;
        const taken = await db.selectFrom('account').select('id').where('username', '=', candidate).executeTakeFirst();
        if (!taken) {
            return candidate;
        }
    }

    throw new Error(`could not find a free username for ${wanted}`);
}

async function accountForDiscordUser(user: DiscordUser) {
    const linked = await db.selectFrom('account').selectAll().where('discord_id', '=', user.id).executeTakeFirst();
    if (linked) {
        return linked;
    }

    const username = await uniqueUsername(user.global_name ?? user.username, user.id);

    // The password column is never used for Discord accounts; a random hash keeps it unusable.
    await db
        .insertInto('account')
        .values({
            username,
            password: bcrypt.hashSync(randomToken(), 10),
            discord_id: user.id,
            registration_ip: null,
            registration_date: toDbDate(new Date())
        })
        .executeTakeFirstOrThrow();

    const created = await db.selectFrom('account').selectAll().where('discord_id', '=', user.id).executeTakeFirstOrThrow();

    console.log(`[auth] created account '${username}' for discord ${user.id}`);

    return created;
}

/**
 * The browser session behind the cookie, or null. Discord is the only way in, so the game page uses
 * this to send anyone without a session straight to Discord instead of loading a client they cannot log into.
 */
export async function sessionFor(req: FastifyRequest): Promise<{ web_token: string; account_id: number; username: string } | null> {
    const webToken = cookie(req, SESSION_COOKIE);
    if (!webToken) {
        return null;
    }

    const session = await db
        .selectFrom('account_session')
        .innerJoin('account', 'account.id', 'account_session.account_id')
        .select(['account_session.web_token', 'account_session.account_id', 'account_session.expires_at', 'account.username'])
        .where('account_session.web_token', '=', webToken)
        .executeTakeFirst();

    if (!session || new Date(session.expires_at) <= new Date()) {
        return null;
    }

    return { web_token: session.web_token, account_id: session.account_id, username: session.username };
}

export function registerDiscordAuth(fastify: FastifyInstance) {
    // The redirect URI must match the Discord application's "Redirects" list character for character.
    // Print it at boot so a mismatch is one glance away instead of a cryptic Discord error page.
    printInfo(`Discord login: ${Environment.discord.enabled ? 'enabled' : 'disabled'}, redirect URI ${Environment.discord.redirectUrl}`);

    fastify.get('/discord', async (_req, reply) => {
        if (!Environment.discord.enabled) {
            return reply.status(503).type('text/html').send(loginErrorMessage('Discord login is not configured.'));
        }

        const state = randomToken();
        setCookie(reply, STATE_COOKIE, state, STATE_TTL_SECONDS);

        const url = new URL('https://discord.com/oauth2/authorize');
        url.searchParams.set('client_id', Environment.discord.clientId);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'identify');
        url.searchParams.set('redirect_uri', Environment.discord.redirectUrl);
        url.searchParams.set('state', state);
        // No prompt param on purpose: `prompt=none` turns the first sign-in into a silent
        // consent_required error instead of showing Discord's authorise screen.

        return reply.redirect(url.toString(), 302);
    });

    fastify.get<{ Querystring: { code?: string; state?: string; error?: string } }>('/discord/callback', async (req, reply) => {
        const expectedState = cookie(req, STATE_COOKIE);
        if (req.query.error) {
            return reply.status(400).type('text/html').send(loginErrorMessage(req.query.error));
        }

        if (!expectedState || !req.query.state || expectedState !== req.query.state || !req.query.code) {
            return reply.status(400).type('text/html').send(loginErrorMessage('The login request expired.'));
        }

        const tokenRes = await fetch(`${DISCORD_API}/oauth2/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: Environment.discord.clientId,
                client_secret: Environment.discord.clientSecret,
                grant_type: 'authorization_code',
                code: req.query.code,
                redirect_uri: Environment.discord.redirectUrl
            })
        });

        if (!tokenRes.ok) {
            console.error(`[auth] discord token exchange failed: ${tokenRes.status} ${await tokenRes.text()}`);
            return reply.status(502).type('text/html').send(loginErrorMessage('Discord rejected the sign-in.'));
        }

        const tokenBody = (await tokenRes.json()) as { access_token: string };
        const user = await discordUsersMe(tokenBody.access_token);
        const account = await accountForDiscordUser(user);

        await db.deleteFrom('account_session').where('expires_at', '<', toDbDate(new Date())).execute();

        const webToken = randomToken();
        await db
            .insertInto('account_session')
            .values({
                web_token: webToken,
                game_token: null,
                account_id: account.id,
                expires_at: toDbDate(new Date(Date.now() + SESSION_TTL_MS))
            })
            .executeTakeFirstOrThrow();

        setCookie(reply, SESSION_COOKIE, webToken, Math.floor(SESSION_TTL_MS / 1000));

        return reply.redirect('/rs2.cgi', 302);
    });

    fastify.get('/discord/session', async (req, reply) => {
        const session = await sessionFor(req);
        if (!session) {
            return reply.status(401).send({ error: 'not signed in' });
        }

        const gameToken = randomToken();
        await db.updateTable('account_session').set({ game_token: gameToken }).where('web_token', '=', session.web_token).executeTakeFirstOrThrow();

        return { username: session.username, token: gameToken };
    });

    fastify.get('/discord/logout', async (req, reply) => {
        const webToken = cookie(req, SESSION_COOKIE);
        if (webToken) {
            await db.deleteFrom('account_session').where('web_token', '=', webToken).execute();
        }

        reply.header('set-cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
        return reply.redirect('/rs2.cgi', 302);
    });
}
