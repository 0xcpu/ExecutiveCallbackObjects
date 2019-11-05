## EnlightenmentState

**[WIP]**

This callback is related to Hyper-V Enlightenments. It is notified in function `HvlPhase2Initialize` only if bit 0 of `HvlpRootFlags` is not set. We still need to trace down wich Enlightenment set or not this bit, it looks like this is done in function `HvlpDetermineEnlightenments` which comes from `HvlPhase0Initialize`.

This still needs a **lot** of investigation since we are not even near to understand how Hyper-V works internally.
