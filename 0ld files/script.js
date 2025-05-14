const FACULTIES = [
  { fac: "Economic and Management Sciences", color: "#f97316" },
  { fac: "Education", color: "#0284c7" },
  { fac: "Engineering", color: "#6b7280" },
  { fac: "Health Sciences", color: "#db2777" },
  { fac: "Humanities", color: "#facc15" },
  { fac: "Law", color: "#dc2626" },
  { fac: "Natural and Agricultural Sciences", color: "#16a34a" },
  { fac: "Theology", color: "#f0abfc" },
];

// Selecting DOM elements
const btn = document.querySelector(".btn-open");
const form = document.querySelector(".lesson-form");
const lessonsList = document.querySelector(".lessons-list");

// Create DOM element
lessonsList.innerHTML = "";

// Load data from Supabase
loadLessons();

async function loadLessons() {
  const res = await fetch(
    "https://yrfhdrzpweryzagjtjbo.supabase.co/rest/v1/LessonsTable",
    {
      headers: {
        apikey:
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlyZmhkcnpwd2VyeXphZ2p0amJvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjI0NDEyNzksImV4cCI6MjAzODAxNzI3OX0.wjJiUY6qitGHiR4A6-1YB4IYPJlgCE0go8TPrrfcIGI",
        authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlyZmhkcnpwd2VyeXphZ2p0amJvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjI0NDEyNzksImV4cCI6MjAzODAxNzI3OX0.wjJiUY6qitGHiR4A6-1YB4IYPJlgCE0go8TPrrfcIGI",
      },
    }
  );
  const data = await res.json();
  createLessonsList(data);
  /*
  const filteredData = data.filter(
    (lesson) => lesson.faculty === "Natural and Agricultural Sciences"
  );
  */
}

function createLessonsList(dataArr) {
  const htmlArr = dataArr.map(
    (lesson) => `<li class="lesson">
    <p>
      ${lesson.lesson}
          <a
              class="source"
              href="${lesson.link}"
              target="_blank"
              >(Source)</a>
      </p>
      <span class="tag" style="background-color: ${
        FACULTIES.find((faculty) => faculty.fac === lesson.faculty).color
      }">${lesson.faculty}</span>
  </li>`
  );

  const html = htmlArr.join("");
  lessonsList.insertAdjacentHTML("afterbegin", html);
}

// Toggle form visibility
btn.addEventListener("click", function () {
  if (form.classList.contains("hidden")) {
    form.classList.remove("hidden");
    btn.textContent = "Close";
  } else {
    form.classList.add("hidden");
    btn.textContent = "Share New Lesson";
  }
});

// =============================================================================

// Example: login and call protected
async function login(username, password) {
  const { token } = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }).then((r) => r.json());
  localStorage.setItem("jwt", token);
}

async function getData(path) {
  const res = await fetch(path, {
    headers: { Authorization: "Bearer " + localStorage.getItem("jwt") },
  });
  console.log(await res.text());
}
