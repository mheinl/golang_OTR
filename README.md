# golang_OTR


# Part 1
Answer the following questions regarding the “Off The Record” protocol created for SMS exchanges. Provide proper justification to each answer.

1. What kind of security does it provide and why? Your answer can be specific to the following 2 security objectives:

- Authentication - which kind(s)?

- Secrecy

2. Does the protocol provide repudiation of the content? Why?
3. Suppose that after the creation of the third shared secret, an attacker can (mystically) obtain that secret. If so, can he now play man in the middle? Justify your answer

# Part 2: 
Implement the OTR protocol in Go language. You should test your implementation by running a demo in which the following conversation between Bob and Alice takes place:

Alice: Lights on

Bob: 30 seconds

Alice: Forward drift?

Bob: Yes

Alice: 413 is in

Bob: Houston, Tranquility base here

Alice: The Eagle has landed

Bob: A small step for a student, a giant leap for the group

Also, implement a third person, Eve, with access to all messages. Alice, Bob, and Eve have their own process.
Output the transcripts of what each person hears and says, and observe whether your answers to part 1 hold.

# Part 3: 
Compare the OTR protocol with the Silent Circle Instant Messaging Protocol (Moscaritolo, Belvin, and Zimmermann, 2012). What are the main differences? What are the advantages and disadvantages of each.

# Our Resources

Presentation:
https://docs.google.com/presentation/d/1K8z5Zl-DjhNyIIha-kb68INW1Ab0ZQTN66wJSiyVygM/edit?usp=sharing

Report:
https://docs.google.com/document/d/1fHFa8VFFwmi9AgSEa6Wu5FwVHk8yHOTb_ne0FnUdHYY/edit?usp=sharing

