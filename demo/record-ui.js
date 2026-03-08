import puppeteer from 'puppeteer';
import { PuppeteerScreenRecorder } from 'puppeteer-screen-recorder';

(async () => {
    console.log('Launching browser...');
    const browser = await puppeteer.launch({
        headless: true,
        defaultViewport: {
            width: 1440,
            height: 900
        }
    });

    const page = await browser.newPage();
    page.on('dialog', async dialog => {
        console.log('Dismissing alert: ', dialog.message());
        await dialog.dismiss();
    });

    console.log('Navigating to http://localhost:3000...');
    await page.goto('http://localhost:3000', { waitUntil: 'networkidle0' });

    // Initial wait for Monaco editor and styling to fully render
    await new Promise(r => setTimeout(r, 2000));

    const recorder = new PuppeteerScreenRecorder(page, {
        followNewTab: false,
        fps: 60,
        videoFrame: {
            width: 1440,
            height: 900,
        },
        aspectRatio: '16:9',
    });

    const savePath = './demo.mp4';
    console.log(`Starting recording to ${savePath}...`);
    await recorder.start(savePath);

    // Wait an extra second before action for viewer pacing
    await new Promise(r => setTimeout(r, 1000));

    console.log('Clicking "Analyze Code"...');
    await page.click('#analyze-btn');

    // Wait 4 seconds for the score ring and progress bar animations to play out
    await new Promise(r => setTimeout(r, 4000));

    console.log('Scrolling down the Analysis Pane...');
    await page.evaluate(() => {
        document.querySelector('.analysis-pane').scrollBy({
            top: 600,
            behavior: 'smooth'
        });
    });

    // Hold briefly at the bottom of the findings
    await new Promise(r => setTimeout(r, 3000));

    console.log('Scrolling back up the Analysis Pane...');
    await page.evaluate(() => {
        document.querySelector('.analysis-pane').scrollBy({
            top: -600,
            behavior: 'smooth'
        });
    });

    // Hold briefly at the top out for the end of the video
    await new Promise(r => setTimeout(r, 1500));

    console.log('Stopping recording...');
    await recorder.stop();

    await browser.close();
    console.log(`Done! Video saved to ${savePath}`);
})();
