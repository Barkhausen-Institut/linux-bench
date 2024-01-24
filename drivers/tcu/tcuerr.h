#ifndef TCU_ERROR_H
#define TCU_ERROR_H

#include <linux/stringify.h>

typedef enum Error {
    // success
    Error_None = 0,
    // TCU errors
    Error_NoMEP,
    Error_NoSEP,
    Error_NoREP,
    Error_ForeignEP,
    Error_SendReplyEP,
    Error_RecvGone,
    Error_RecvNoSpace,
    Error_RepliesDisabled,
    Error_OutOfBounds,
    Error_NoCredits,
    Error_NoPerm,
    Error_InvMsgOff,
    Error_TranslationFault,
    Error_Abort,
    Error_UnknownCmd,
    Error_RecvOutOfBounds,
    Error_RecvInvReplyEPs,
    Error_SendInvCreditEp,
    Error_SendInvMsgSize,
    Error_TimeoutMem,
    Error_TimeoutNoC,
    Error_PageBoundary,
    Error_MsgUnaligned,
    Error_TLBMiss,
    Error_TLBFull,
    Error_NoPMPEp,
    // SW Errors
    Error_InvArgs,
    Error_ActivityGone,
    Error_OutOfMem,
    Error_NoSuchFile,
    Error_NotSup,
    Error_NoFreeTile,
    Error_InvalidElf,
    Error_NoSpace,
    Error_Exists,
    Error_XfsLink,
    Error_DirNotEmpty,
    Error_IsDir,
    Error_IsNoDir,
    Error_EPInvalid,
    Error_EndOfFile,
    Error_MsgsWaiting,
    Error_UpcallReply,
    Error_CommitFailed,
    Error_NoKernMem,
    Error_NotFound,
    Error_NotRevocable,
    Error_Timeout,
    Error_ReadFailed,
    Error_WriteFailed,
    Error_Utf8Error,
    Error_BadFd,
    Error_SeekPipe,
    // networking
    Error_InvState,
    Error_WouldBlock,
    Error_InProgress,
    Error_AlreadyInProgress,
    Error_NotConnected,
    Error_IsConnected,
    Error_InvChecksum,
    Error_SocketClosed,
    Error_ConnectionFailed,
} Error;

char *error_to_str(Error e);

#endif // TCU_ERROR_H
