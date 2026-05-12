import https from 'https';

const BOT_NAME         = '𝐕𝐄𝐂𝐓𝐎𝐑 𝐂𝐑𝐀𝐒𝐇𝐄𝐑';
const BOT_REPO         = 'https://github.com/your-repo';
const WHATSAPP_CHANNEL = 'https://whatsapp.com/channel/0029VbD1fqe5kg6xDhBs5G3M';
const BANNER_URL       = 'https://files.catbox.moe/a1i7kj.png';
const NEWSLETTER_JID   = '120363408935865710@newsletter';

function fetchBuffer(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end',  () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        }).on('error', reject);
    });
}

export async function sendSessionMessage(sock, jid, sessionId) {
    const bannerBuffer = await fetchBuffer(BANNER_URL);
    await sock.sendMessage(jid, {
        image: bannerBuffer,
        caption: `𝐕𝐄𝐂𝐓𝐎𝐑 𝐂𝐑𝐀𝐒𝐇𝐄𝐑 𝐒𝐄𝐒𝐒𝐈𝐎𝐍\n\n${sessionId}`,
        footer: `Powered by Zentrix Tech`,
        nativeFlow: [
            { text: '📋 𝐂𝐎𝐏𝐘 𝐒𝐄𝐒𝐒𝐈𝐎𝐍', copy: sessionId },
            { text: '📦 𝐁𝐎𝐓 𝐑𝐄𝐏𝐎', url: BOT_REPO },
            { text: '📢 𝐖𝐀 𝐂𝐇𝐀𝐍𝐍𝐄𝐋', url: WHATSAPP_CHANNEL }
        ],
        externalAdReply: {
            title: BOT_NAME,
            body: 'WhatsApp · Verified',
            url: WHATSAPP_CHANNEL,
            thumbnail: bannerBuffer,
            mediaType: 1,
            showAdAttribution: true,
            renderLargerThumbnail: false
        },
        contextInfo: {
            forwardedNewsletterMessageInfo: {
                newsletterJid: NEWSLETTER_JID,
                newsletterName: BOT_NAME,
                serverMessageId: Math.floor(Math.random() * 999999)
            },
            isForwarded: true,
            forwardingScore: 999
        }
    });
}
