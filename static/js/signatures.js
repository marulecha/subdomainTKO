const signatures = [
    {
        name: "AWS S3 Bucket",
        cname: ["s3.amazonaws.com"],
        pattern: "NoSuchBucket",
        description: "The CNAME points to an Amazon S3 bucket that has been deleted or does not exist.",
        remediation: "To take over this subdomain, log into your AWS account, go to the S3 service, and create a new bucket with the exact name of the vulnerable subdomain. Ensure you have the rights to set it to public hosting if necessary.",
        link: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html"
    },
    {
        name: "GitHub Pages",
        cname: ["github.io"],
        pattern: "There isn't a GitHub Pages site here",
        description: "The subdomain points to a GitHub Pages repository that has been removed or renamed.",
        remediation: "Create a new repository on GitHub. Go to Settings > Pages, and add the vulnerable subdomain as your Custom Domain. GitHub will verify the DNS record (which already points to them) and serve your content.",
        link: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site"
    },
    {
        name: "Shopify",
        cname: ["shops.myshopify.com"],
        pattern: "Sorry, this shop is currently unavailable",
        description: "The subdomain is configured to point to a Shopify store that is no longer active.",
        remediation: "Sign up for a new Shopify store. In the Dashboard under Settings > Domains, select 'Connect existing domain' and enter the vulnerable subdomain.",
        link: "https://help.shopify.com/en/manual/domains/add-a-domain/connecting-domains"
    },
    {
        name: "Heroku",
        cname: ["herokudns.com", "herokuapp.com"],
        pattern: "No such app",
        description: "The DNS record points to a Heroku application that has been deleted.",
        remediation: "Create a new app on Heroku. Use the Heroku CLI to add the custom domain: `heroku domains:add vulnerable.example.com -a your-new-app-name`.",
        link: "https://devcenter.heroku.com/articles/custom-domains"
    },
    {
        name: "Azure App Service",
        cname: ["azurewebsites.net"],
        pattern: "404 Web Site not found",
        description: "The subdomain points to an Azure web app that no longer exists.",
        remediation: "Create a new Azure App Service resource. Under Custom domains, add the vulnerable subdomain. Azure will verify the CNAME record.",
        link: "https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain"
    },
    {
        name: "Zendesk",
        cname: ["zendesk.com"],
        pattern: "Help Center Closed",
        description: "Points to a closed or deleted Zendesk support portal.",
        remediation: "Register a new Zendesk account and set the host mapping in the admin panel to the vulnerable subdomain.",
        link: "https://support.zendesk.com/hc/en-us/articles/4408803273114-Host-mapping-Changing-the-URL-of-your-help-center"
    }
];
