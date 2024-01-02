using SampleWebApi.Common;

namespace SampleWebApi.Features
{
    public class UserErrors
    {
        public static Error AlreadyExist(string fullname) =>
            new Error("User.AlreadyExist", $"User {fullname} already exist");

        public static Error NotFound() =>
            new Error("User.NotFound", "User not found");

        public static Error NoDataFound() =>
            new Error("User.NoDataFound", "No Data found");

        public static Error InputsNotMet() =>
            new Error("Inputs.NotMet", "Conditions are not met please check your inputs");
    }
}
