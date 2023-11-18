# DN :heavy_dollar_sign:- DNS Resolver with Advertisements :moneybag: :money_with_wings: :dollar:

Tired of companies snooping through your DNS traffic? Don't you wish you could get advertisements with your DNS records?

We're introducing the innovative, privacy-focused, ad-supported DNS resolver - **DN$**! Traditional DNS resolvers provided by your internet service provider, cloudflare, or google could be tracking your internet activity and selling it to third-party data vendors. Those vendors will repackage and resell your information to the government or ~Facebook~ Meta. 

The team at DN$ wants to fix that and cut out these nefarious actors... until we've amassed a critical number of users to exploit.

In order to support such a radically new business model, our service needs to serve adverts because $INSERT_FAKE_REASONS. 

Fortunately, we offer a lifetime subscription of DN$ for customers to see reduced ads[^1]! 

[^1]: advertisement reduction of 3% 

Open source and built in rust - our software is secure and blazingly fast because it is open source and built in rust. Our backend is based on a ~monolith~, ~microservice~, ~modular monolith~ $NEW_DEVELOPER_FAD. Rather than hijacking NXDOMAINs in the old, boring ways[^2][^3], we've innovated the DNS by adding sponsorships to almost all our DNS responses. Moreover, we've eschewed "RFCs" and "backwards compatability" for the sake of progress. Did I mention that it's built in rust therefore it's safe and fast?

[^2]: https://www.theregister.com/2009/08/17/dzuiba_virgin_media_opendns/
[^3]: https://en.wikipedia.org/wiki/DNS_hijacking


As a corporate entity, our executives are not liable for prison time and will probably only be fined small financial penalties for any serious crimes we commit. However, we **promise** that we are NOT doing *anything* nefarious like tracking and selling your user data and internet behavior[^4]. We will also not be using the data (we are *not* collecting :wink: ) to train AI models to make ourselves rich.

[^4]: we are not doing anything... *yet*


Just send your DNS queries to `35.223.197.204` :). Try it out now:

## Unix/MacOS
```
dig @35.223.197.204 reddit.com
```

## Windows Systems (requires powershell)
```
Resolve-DnsName -Name reddit.com -Server 35.223.197.204
```

# Internal Roadmap (DO NOT LEAK) 

Q1 2024
- Develop our entire software stack in Golang :fearful:
- Re-write our entire stack to Rust because any language that isn't rust is **garbage** :broken_heart:
- Migrate to microservices :anguished:
- Migrate to modular monoliths :astonished:
- Migrate back to microservices :disappointed_relieved:
- Migrate back to the our original architecture :heart:

Q2 2024
- April 1st 2024: Release v0.1 :confetti_ball:
- Aggressively market our company to VC funds :dizzy_face:
- Make impossible promises to investors and users :revolving_hearts:
- Collect customer feature requests into public roadmap :sparkling_heart:
- Sell lifetime subscriptions :moneybag:

Q3 2024
- Balk on our privacy promises once we get traction and sell user data to third party vendors :joy: :joy: :joy:
- Pretend to work on public roadmap, really work on more tracking and advertisements :joy: :joy: :joy:
- [Acquire smaller software companies and modify their software to harvest data](https://techcrunch.com/2024/03/26/facebook-secret-project-snooped-snapchat-user-traffic/) :point_up:

Q4 2024 ( :moneybag: :moneybag: :moneybag: :moneybag: )
- Renege on lifetime subscription, do not give them refunds :money_with_wings: :money_with_wings: :money_with_wings:
- Obfuscate location of investor and customer money with convoluted mixing + laundering of cryptocurrency :money_with_wings: :money_with_wings: :money_with_wings:
- Close down the company and service because we're "not profitable" :disappointed: :cry: :triumph:

/s

## How to run
```
cargo build --release
./target/release/adcache --help
```



