# Replies to Ian Gabriel Barish's Post

**Discussion:** Post Video 2 (June 16) and Submit Peer Feedback Report (June 21) - Group 7

---

## Ian Gabriel Barish (Original Post)

**Date:** Jun 17, 10:48am (edited Jun 17, 10:53am)

Sorry for the video sound, here's the subtitles if you need it:
<https://github.com/Ian-Costa18/Cybersecurity-Practicum/blob/progress-report-3/Practicum%20Work/Videos/Ian%20Barish%20-%20Video%202.srt>

My Progress Report 2:
<https://github.com/Ian-Costa18/Cybersecurity-Practicum/blob/progress-report-2/Practicum%20Work/Progress%20Reports/Progress%20Report%202.pdf>

Scope for MVP:
<https://github.com/Ian-Costa18/Cybersecurity-Practicum/blob/progress-report-2/docs/mvp.md>

The rest of the documentation:
<https://github.com/Ian-Costa18/Cybersecurity-Practicum/tree/progress-report-2/docs>

*(Attachment: Ian Barish - Video 2.mkv)*

---

## Reply 1 — Joanna Delarosa Flores

**Date:** Jun 17, 3:45pm

Hello Ian, thank you for sharing your project readings and good work. You are doing well on your project and research. I really see the effort you put into testing your solutions. I see that you moved away from the multi-signature cryptography but it does not look like this weakened your contribution. I see this as a practical solution - the use of standard credential-backed authentication. This lowers the friction of users and speeds up MVP development. The true value for your proxy is the enforcement of multi-party approval. The solution you presented still prevents unilateral actions from any one maintainer.

Here is one good reference I found: <https://www.fireblocks.com/blog/mpc-vs-multi-sig>. It explained on this site, "MPC addresses both problems structurally. The full private key never exists, so there is nothing to steal through a single compromise. And because signing happens off-chain at the cryptographic layer, MPC's security properties are consistent across chains, regardless of how any given protocol handles transaction authorization natively."

With your question: Is package publishing the right place to start? I believe it is since this is an excellent starting point. Package publishing is always a major supply-chain risk, and it is easy to demo. The consequences of compromise are high and your system directly addresses this via multi-party approval. With your worry of over-scoping or under-scoping, I think if you try to tackle login portal flows it will add more complexity and slow your MVP ship. Your use case of package publishing is not too limited - it focuses demonstration, and is strong. It is a clearly defined workflow with huge security value and immediate applicability. Hope this helps!

---

## Reply 2 — Thea Galano Nudo

**Date:** Jun 18, 1:57pm

I think package publishing is the right first place to build.
To me, it does not look under-scoped, because it still proves the main goal of your project: that one person should not be able to perform a sensitive action alone. It also does not feel too big, as long as the first version focuses on one complete package-publishing workflow.

In my opinion, you should start with a simple working version of that flow like this:

1. Requester submits package
2. System saves the package and creates a hash
3. Approvers are notified (for example, 5 approvers, or more, depending on your plan)
4. 3 out of 5 approvers must approve, so the request does not depend on every single approver being available
5. If someone denies, they give a short reason and the request stops
6. The denial reason is saved in the audit log
7. If approved, the system checks the hash again
8. Package is published
9. The final result is recorded in the audit log

After this basic workflow is working, you can expand it to the other use cases you mentioned, such as shared accounts, portals, or second-factor login. Getting this first flow right will make the rest of the project easier to build and explain.
So to answer your question: yes, I think package publishing is the right MVP. I recommend focusing on that workflow first, then moving on to the other use cases once it works.

---

## Reply 3 — Andrey M Makhanov

**Date:** Jun 19, 12:10am

Hi Ian,

I think it's great that you've decided to shift away from your original idea so early in the project. I think it's best to refine ideas early in the project than later.

In Github, you can sign your commits with your private key (you give the public key to github.com). The signing of commits verifies that the commit has been signed by that user account (as removing the public key from Github will invalidate all the previous signatures). I believe that the exact state of commit is signed so that if someone tampers with the commit, the commit will be considered "invalid". I am curious if you can use similar methodology. I guess in the paper you would have to argue why this proxy is important and why would people use it rather than just using Github and having multiple users "approve" a pull request to merge the code into the codebase.

I would also consider doing a "risk assessment" to perhaps strengthen your paper. For example, what would happen if this proxy is compromised? Are there any safe-guards in place to prevent packages from being published if the "approver" or "approvers" are compromised (you've mentioned that the method is adequate for the single-compromise threat model)?

Also, another question to consider is whether a single denial rule is a good idea. I know that in the PHP (web coding) community, there was a question of whether to release a PHP version called PHP 6 or skip to PHP 7 and top contributors voted for the rule. Even though the naming scheme didn't matter that much, about a third voted to name the version PHP 6 and 2/3 voted to name the next version PHP 7 (<https://wiki.php.net/rfc/php6>). I believe that if the project is large enough and there are a ton of votes, there will always be a few people that will not approve changes. Can certain users override the votes? Maybe you could also implement some form of weighting mechanism where certain votes count more than others and you need a certain threshold for the artifact to be approved.

I hope this helps and I can't wait to see the next iteration.

---

## Reply 4 — Ian Gabriel Barish (response to Andrey)

**Date:** Jun 20, 12:40pm

Hey Andrey, great feedback.
I do understand that GitHub provides this as an option, but not everyone uses GitHub to manage projects. And there's still the issue of maintainers on the package repository being allowed to publish a package directly to the package repository without it having to go through GitHub. That's an argument that I'll have to keep working on for the final paper.

The risk assessment has been started! I currently have a threat model that needs quite a bit of work, but it's there. You can see it here if you'd like:
<https://github.com/Ian-Costa18/Cybersecurity-Practicum/blob/progress-report-2/docs/threat-model.md>

I see where you're coming from with a single denial rule stopping everything. I think ideally as a security project, these issues are more of a design and contribution guideline. This vote is really only done as a sign off, no design decisions should need to be made because of it, but I could see the issue of a disgruntled contributor not getting their way during design then taking it out on the project at the final sign off.

---

## Reply 5 — Andrey M Makhanov (follow-up)

**Date:** Jun 21, 6:18pm

Hi Ian,

Thanks so much for your comments. I was wondering if you could make it so that anyone can "host" this proxy. You would still need "head" managers that would set this proxy up but it would function without having this host trust issue.

---

## Reply 6 — Ian Gabriel Barish (response to Andrey follow-up)

**Date:** Jun 22, 10:05pm

@Andrey M Makhanov yes, it's open source and I'm planning on adding a docker container tonight, so definitely hostable by everyone! The idea is organizations would have their own instance, but if that instance gets compromised, it still has security implications. That's what I mean by needing to trust the proxy.

---

## Reply 7 — Brandon Wu (He/Him)

**Date:** Jun 19, 2:35pm

I think the multi-approver using a cryptographically verifiable approval sounds great. I'm curious (as you go through writing up the methodology) if there are tradeoffs you are sacrificing by taking this approach as opposed to the multi-signature approach. Nothing to build, but a discussion item I think is worth discussing in your paper later on.

As for the MVP, I think a code publishing workflow fits well. There are likely all sorts of cases where publication of something could require multiple approvals (often they are tied to approval workflows which could also use multi-approver states). For example, there could be multiple approvals required for advertising or marketing messages posted in regulated industries. I'm sure there are other cases too, so I think the publication workflow is generalizable.

I am still unclear on how the proxy is enforced. Typically, in a code or artifact publishing workflow there is a central code repository that can enforce the controls. How will you build the system such that the proxy is not by-passable? Is this a POC where the proxy development is the contribution that can be adopted by a SCM system in the future (like a Gitlab or Github)? It might be interesting to explore the possibility of actually enforcing this for an example code management system to prove that it can be done.

Anyways, I like the shift in approach here and glad you were able to pivot early before a lot of building was already done.

---

## Reply 8 — Ian Gabriel Barish (response to Brandon)

**Date:** Jun 20, 12:52pm

Hi Brandon, great feedback as well.
Definitely there are tradeoffs, and the system I'm building for the MVP may not work for everyone, but I'm imagining that the paper will advocate for all of the ways you could add multi-signature/approval as a security control, and my final program may include a switch to toggle between the two (that's way outside of current scope though).

Regarding the enforcement of the proxy, this is where I can only do so much and must advocate for this POC of the feature to be added to the package repository. The current scheme is the proxy holds the only publishing token (and therefore is the only thing allowed to push a package), then when a maintainer wants to publish, they do so using their normal tools, but setting the endpoint as the proxy so the package is uploaded to the proxy instead of the package repository. After approval, the package is published from the proxy to the repository automatically. It's all HTTP behind the hood, so it's actually pretty smooth.

---

## Reply 9 — Mikhail Vyacheslavovich Surikov

**Date:** Jun 21, 5:30pm

Nice progress! It must not have been easy to let go of the first idea =).

I wanted to better understand what system the users would be logging into with their password + one-time code, and once logged in, what actions would be available to them? Given that they are still logging in somewhere, you'd still have concerns around the server-side process; can you help me understand why this 2nd workflow is better in this context?

Overall the workflow looks good. Given the time constraints, you may want to build what you can and leave the rest for later.

Good luck, and I look forward to your next update!

---

## Reply 10 — Kenneth Kim

**Date:** Jun 21, 7:12pm

Nice update. I like that you challenged your original idea before jumping into code. The shift from crypto style threshold signatures to credential backed approvals makes sense, especially if the goal is something people can actually use in an enterprise setting.

From my experience in manufacturing cybersecurity, this reminds me a lot of change control for sensitive actions. The approval workflow itself is important, but the audit trail may be just as important. I would make sure the system clearly records who requested the action, who approved it, when it was approved, what exact action was approved, and whether the approval expired before use.

For the MVP, I think package publishing is a good first slice. It is narrow enough to build end-to-end, but still security relevant because one bad publish can create real supply chain risk.
