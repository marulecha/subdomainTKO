// Provider fingerprints for subdomain takeover checks.
// Source of truth for current status: https://github.com/EdOverflow/can-i-take-over-xyz
//
// match:        CNAME suffixes (strings) or RegExps tested against every host in the CNAME chain.
// nxdomainOnly: the provider is only exploitable when the CNAME target does not resolve.
// fingerprint:  text the provider serves for an unclaimed resource. Browsers cannot read
//               cross-origin responses, so the user confirms this by opening the host.
// status:       'vulnerable' (known exploitable) or 'edge' (exploitable only in some setups).
const signatures = [
    {
        name: "AWS S3",
        match: [/(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$/],
        fingerprint: "NoSuchBucket / The specified bucket does not exist",
        status: "vulnerable",
        description: "The CNAME points to an Amazon S3 bucket that has been deleted or never existed.",
        claim: "Create an S3 bucket whose name equals the full subdomain, in the region the CNAME points to, and enable static website hosting.",
        docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html"
    },
    {
        name: "AWS Elastic Beanstalk",
        match: ["elasticbeanstalk.com"],
        nxdomainOnly: true,
        status: "vulnerable",
        description: "The CNAME points to an Elastic Beanstalk environment name that is no longer registered.",
        claim: "Create an Elastic Beanstalk environment in the same region using the environment name from the CNAME target.",
        docs: "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html"
    },
    {
        name: "Microsoft Azure",
        match: [
            "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
            "blob.core.windows.net", "azure-api.net", "azurehdinsight.net", "azureedge.net",
            "azurecontainer.io", "database.windows.net", "azuredatalakestore.net",
            "search.windows.net", "azurecr.io", "redis.cache.windows.net",
            "servicebus.windows.net", "visualstudio.com"
        ],
        nxdomainOnly: true,
        status: "vulnerable",
        description: "The CNAME points to an Azure resource name that has been released.",
        claim: "Create an Azure resource of the same type with the name from the CNAME target, then add the subdomain under Custom domains.",
        docs: "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"
    },
    {
        name: "GitHub Pages",
        match: ["github.io"],
        fingerprint: "There isn't a GitHub Pages site here.",
        status: "vulnerable",
        description: "The subdomain points to a GitHub Pages site that has been removed, renamed or never configured the custom domain.",
        claim: "Create a repository, enable Pages, and set the subdomain as its custom domain under Settings > Pages.",
        docs: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages"
    },
    {
        name: "Bitbucket",
        match: ["bitbucket.io"],
        fingerprint: "Repository not found",
        status: "vulnerable",
        description: "The subdomain points to a Bitbucket Cloud static site that no longer exists.",
        docs: "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/"
    },
    {
        name: "Heroku",
        match: ["herokuapp.com", "herokudns.com"],
        fingerprint: "No such app",
        status: "edge",
        description: "The DNS record points to a Heroku app or DNS target that has been deleted. Heroku now issues random DNS targets, so most records cannot be claimed.",
        claim: "Create an app and run `heroku domains:add <subdomain> -a <app>`. This only works when the old DNS target can be reproduced.",
        docs: "https://devcenter.heroku.com/articles/custom-domains"
    },
    {
        name: "Shopify",
        match: ["myshopify.com"],
        fingerprint: "Sorry, this shop is currently unavailable.",
        status: "edge",
        description: "The subdomain is configured for a Shopify store that is no longer active.",
        claim: "Create a store and connect the subdomain under Settings > Domains.",
        docs: "https://help.shopify.com/en/manual/domains/add-a-domain/connecting-domains"
    },
    {
        name: "Netlify",
        match: ["netlify.app", "netlify.com"],
        fingerprint: "Not Found - Request ID",
        status: "edge",
        description: "The subdomain points to Netlify but no site claims it.",
        docs: "https://docs.netlify.com/domains-https/custom-domains/"
    },
    {
        name: "Zendesk",
        match: ["zendesk.com"],
        fingerprint: "Help Center Closed",
        status: "edge",
        description: "The subdomain points to a Zendesk help center that has been closed or deleted.",
        docs: "https://support.zendesk.com/hc/en-us/articles/4408803273114"
    },
    {
        name: "Ghost",
        match: ["ghost.io"],
        fingerprint: "Failed to resolve DNS path for this host",
        status: "vulnerable",
        description: "The subdomain points to a Ghost(Pro) publication that no longer exists.",
        docs: "https://ghost.org/help/custom-domains/"
    },
    {
        name: "Help Scout",
        match: ["helpscoutdocs.com"],
        fingerprint: "No settings were found for this company:",
        status: "vulnerable",
        description: "The subdomain points to a Help Scout Docs site that has been removed.",
        docs: "https://docs.helpscout.com/article/42-setup-custom-domain"
    },
    {
        name: "Pantheon",
        match: ["pantheonsite.io"],
        fingerprint: "The gods are wise, but do not know of the site which you seek.",
        status: "vulnerable",
        description: "The subdomain points to a Pantheon site that has been deleted.",
        docs: "https://docs.pantheon.io/guides/domains"
    },
    {
        name: "Surge.sh",
        match: ["surge.sh"],
        fingerprint: "project not found",
        status: "vulnerable",
        description: "The subdomain points to a Surge project that has been torn down.",
        docs: "https://surge.sh/help/adding-a-custom-domain"
    },
    {
        name: "WordPress.com",
        match: ["wordpress.com"],
        fingerprint: "Do you want to register",
        status: "vulnerable",
        description: "The subdomain points to a WordPress.com site that no longer exists.",
        docs: "https://wordpress.com/support/domains/connect-subdomain/"
    },
    {
        name: "Tumblr",
        match: ["domains.tumblr.com"],
        fingerprint: "Whatever you were looking for doesn't currently exist at this address.",
        status: "edge",
        description: "The subdomain points to a Tumblr blog that has been deleted or renamed.",
        docs: "https://help.tumblr.com/hc/en-us/articles/231256548-Custom-domains"
    },
    {
        name: "Webflow",
        match: ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        fingerprint: "The page you are looking for doesn't exist or has been moved.",
        status: "edge",
        description: "The subdomain points to Webflow but no published site claims it.",
        docs: "https://university.webflow.com/lesson/manually-connect-a-custom-domain"
    },
    {
        name: "Ngrok",
        match: ["ngrok.io"],
        fingerprint: "Tunnel *.ngrok.io not found",
        status: "vulnerable",
        description: "The subdomain points to an ngrok tunnel that is no longer running.",
        docs: "https://ngrok.com/docs/network-edge/domains-and-tcp-addresses/"
    },
    {
        name: "Agile CRM",
        match: ["agilecrm.com"],
        fingerprint: "Sorry, this page is no longer available.",
        status: "vulnerable",
        description: "The subdomain points to an Agile CRM landing page that has been removed.",
        docs: "https://www.agilecrm.com/"
    },
    {
        name: "Strikingly",
        match: ["s.strikinglydns.com"],
        fingerprint: "PAGE NOT FOUND.",
        status: "vulnerable",
        description: "The subdomain points to a Strikingly site that has been removed.",
        docs: "https://support.strikingly.com/hc/en-us/articles/215046947"
    },
    {
        name: "Uberflip",
        match: ["read.uberflip.com"],
        fingerprint: "The URL you've accessed does not provide a hub.",
        status: "vulnerable",
        description: "The subdomain points to an Uberflip hub that no longer exists.",
        docs: "https://help.uberflip.com/"
    },
    {
        name: "Gemfury",
        match: ["furyns.com"],
        fingerprint: "404: This page could not be found.",
        status: "vulnerable",
        description: "The subdomain points to a Gemfury account that no longer exists.",
        docs: "https://gemfury.com/help/custom-domains"
    },
    {
        name: "LaunchRock",
        match: ["launchrock.com"],
        fingerprint: "It looks like you may have taken a wrong turn somewhere.",
        status: "vulnerable",
        description: "The subdomain points to a LaunchRock page that has been removed.",
        docs: "https://www.launchrock.com/"
    },
    {
        name: "Canny",
        match: ["canny.io"],
        fingerprint: "Company Not Found",
        status: "vulnerable",
        description: "The subdomain points to a Canny board that no longer exists.",
        docs: "https://help.canny.io/en/articles/1394564-custom-domains"
    }
];
