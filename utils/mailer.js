const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendClaimNotification = async (ownerEmail, ownerName, interactorName, interactorPhone, itemName, itemCategory) => {
    
    const isLostItem = itemCategory === 'lost';
    const subject = isLostItem ? `Good News! Your Lost Item "${itemName}" Has Been Found!` : `Your Item "${itemName}" Has Been Claimed!`;
    const interactionText = isLostItem ? 'found by' : 'claimed by';

    const mailOptions = {
        from: `"NITW Lost & Found" <${process.env.EMAIL_USER}>`,
        to: ownerEmail,
        subject: subject,
        html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <p>Dear ${ownerName},</p>
                <p>We have an update regarding the item you posted, <strong>${itemName}</strong>.</p>
                <p>It was ${interactionText}: <strong>${interactorName}</strong>.</p>
                <p>You can contact them at: <strong>${interactorPhone || 'Not provided'}</strong> to coordinate the return.</p>
                <p>Please log in to the portal to view the updated status.</p>
                <p>Sincerely,<br>The NITW Lost & Found Team</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Notification email sent successfully to ${ownerEmail}.`);
    } catch (error) {
        console.error('Error sending notification email:', error);
    }
};

module.exports = { sendClaimNotification };
    